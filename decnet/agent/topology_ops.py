"""Agent-side topology apply/teardown/state primitives.

Wraps the compose + bridge machinery from :mod:`decnet.engine.deployer`
so the agent can drive a topology without ever touching the master's
sqlmodel repo.  The master-side ``deploy_topology`` always calls
``transition_status(repo, …)`` which is useless (and unreachable) on
an agent — here we operate purely on a hydrated dict + the local
:class:`TopologyStore`.

v1 constraint: one topology per agent.  A second apply for a different
``topology_id`` triggers an on-the-spot teardown of the predecessor
before the new apply proceeds — master is authoritative.
"""
from __future__ import annotations

import asyncio
import subprocess  # nosec B404
from typing import Any

import docker

from decnet.agent.topology_store import (
    TopologyStore,
    observed,
)
from decnet.engine.deployer import (
    _compose,
    _compose_with_retry,
    _teardown_order,
    _topology_compose_path,
    _topology_compose_project,
)
from decnet.logging import get_logger
from decnet.network import create_bridge_network, remove_bridge_network
from decnet.topology.compose import (
    _network_name as _topology_network_name,
    write_topology_compose,
)
from decnet.topology.hashing import canonical_hash
from decnet.topology.validate import (
    ValidationError,
    errors as _validation_errors,
    validate as _validate_topology,
)

log = get_logger("agent.topology_ops")


class HashMismatch(RuntimeError):
    """Raised when the master-provided version_hash doesn't match what we
    hash locally — suggests serialisation drift.  We fail loudly rather
    than silently papering over a schema mismatch."""


def _topology_id(hydrated: dict[str, Any]) -> str:
    topo = hydrated.get("topology") or {}
    tid = topo.get("id")
    if not tid:
        raise ValueError("hydrated topology missing topology.id")
    return str(tid)


def _check_hash_and_validate(hydrated: dict[str, Any], version_hash: str) -> str:
    """Verify hash integrity and structural validity; return topology_id."""
    local_hash = canonical_hash(hydrated)
    if local_hash != version_hash:
        raise HashMismatch(
            f"master hash {version_hash!r} does not match agent hash "
            f"{local_hash!r} — refusing to apply"
        )
    issues = _validate_topology(hydrated)
    if _validation_errors(issues):
        raise ValidationError(issues)
    return _topology_id(hydrated)


async def _teardown_superseded(topology_id: str, store: TopologyStore) -> None:
    """Tear down the current topology if it differs from topology_id.

    Master is authoritative — a different pinned topology (fully applied,
    partially applied, or drifted) is torn down before the new apply proceeds.
    Refusing with 409 would leave the agent stuck in a state only a human
    could resolve.
    """
    existing = store.current()
    if existing is None or existing.topology_id == topology_id:
        return
    log.info(
        "superseding topology %s with %s on master authority",
        existing.topology_id, topology_id,
    )
    try:
        await teardown(existing.topology_id, store)
    except Exception as exc:  # noqa: BLE001 — we still want to try applying
        log.warning(
            "best-effort teardown of superseded topology %s failed: %s",
            existing.topology_id, exc,
        )
        # Hard-clear the store row so the new apply isn't blocked by a
        # half-torn-down predecessor.  Leftover docker objects surface via
        # the next heartbeat's observed block.
        store.clear(existing.topology_id)


def _materialise(hydrated: dict[str, Any], topology_id: str) -> None:
    """Create bridge networks, write compose file, and bring up containers.

    Sync/blocking — callers must dispatch via asyncio.to_thread.

    ``--always-recreate-deps`` keeps service containers' netns shares
    fresh: every decky service joins its base's netns via
    ``network_mode: container:<base>``, and that share is bound at
    service start time. If a base is recreated (e.g. when ``ports:``
    changes after toggling ``forwards_l3``) but compose decides the
    services are unchanged, the services keep a stale netns FD
    pointing at the destroyed base — they end up in an empty
    namespace with only ``lo``, and external traffic hits a closed
    port on the live base. Forcing dependents to recreate alongside
    the base is the cheapest way to make this race impossible.
    """
    compose_path = _topology_compose_path(topology_id)
    compose_project = _topology_compose_project(topology_id)
    client = docker.from_env()
    for lan in hydrated["lans"]:
        net_name = _topology_network_name(topology_id, lan["name"])
        create_bridge_network(client, net_name, lan["subnet"], internal=not lan["is_dmz"])
    write_topology_compose(hydrated, compose_path)
    _compose_with_retry(
        "up", "--build", "-d", "--always-recreate-deps",
        compose_file=compose_path, project=compose_project,
    )


async def apply(
    hydrated: dict[str, Any],
    version_hash: str,
    store: TopologyStore,
) -> None:
    """Materialise *hydrated* on this agent and record it in *store*.

    Raises:
      HashMismatch: master and agent disagree on the canonical hash —
        don't touch docker, fail the apply.
      ValidationError: topology fails structural validation.
      Any docker / compose error propagates up; the endpoint maps it
        to 500 and records the message on the store row.
    """
    topology_id = _check_hash_and_validate(hydrated, version_hash)
    await _teardown_superseded(topology_id, store)
    await asyncio.to_thread(_materialise, hydrated, topology_id)
    store.put(topology_id, version_hash, hydrated)
    log.info("topology %s applied on agent (%d LANs)", topology_id, len(hydrated["lans"]))


async def teardown(
    topology_id: str,
    store: TopologyStore,
) -> None:
    """Tear down *topology_id* on this agent.  Idempotent: if there's no
    record and no compose file, it's a no-op that still returns cleanly."""
    row = store.current()
    # Prefer the stored hydrated blob — it's what we applied with.  If
    # it's gone (db wiped) but compose-file lingers, we still try to
    # compose-down and delete bridges by scanning the compose file's
    # LAN membership list via the hydrated blob if available.
    hydrated = row.hydrated if row and row.topology_id == topology_id else None
    compose_path = _topology_compose_path(topology_id)
    compose_project = _topology_compose_project(topology_id)
    client = docker.from_env()

    def _dismantle() -> None:
        if compose_path.exists():
            try:
                _compose(
                    "down", "--remove-orphans",
                    compose_file=compose_path, project=compose_project,
                )
            except subprocess.CalledProcessError as exc:
                log.warning(
                    "topology %s compose down failed (continuing): %s",
                    topology_id, exc,
                )
        if hydrated is not None:
            for lan_name in _teardown_order(hydrated["lans"]):
                net_name = _topology_network_name(topology_id, lan_name)
                remove_bridge_network(client, net_name)
        if compose_path.exists():
            compose_path.unlink()

    await asyncio.to_thread(_dismantle)
    store.clear(topology_id)
    log.info("topology %s torn down on agent", topology_id)


def state(store: TopologyStore) -> dict[str, Any]:
    """Snapshot-plus-live-observation — the shape the heartbeat embeds."""
    row = store.current()
    try:
        obs = observed(docker.from_env())
    except Exception as exc:  # noqa: BLE001 — docker socket may be gone
        obs = {"error": str(exc)[:200]}
    if row is None:
        return {
            "topology_id": None,
            "applied_version_hash": None,
            "applied_at": None,
            "last_error": None,
            "observed": obs,
        }
    return {
        "topology_id": row.topology_id,
        "applied_version_hash": row.applied_version_hash,
        "applied_at": row.applied_at,
        "last_error": row.last_error,
        "observed": obs,
    }


__all__ = ["apply", "teardown", "state", "HashMismatch"]
