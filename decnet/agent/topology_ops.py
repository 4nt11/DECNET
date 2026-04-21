"""Agent-side topology apply/teardown/state primitives.

Wraps the compose + bridge machinery from :mod:`decnet.engine.deployer`
so the agent can drive a topology without ever touching the master's
sqlmodel repo.  The master-side ``deploy_topology`` always calls
``transition_status(repo, …)`` which is useless (and unreachable) on
an agent — here we operate purely on a hydrated dict + the local
:class:`TopologyStore`.

v1 constraint: one topology per agent.  A second apply for a different
``topology_id`` raises :class:`AlreadyApplied` (the endpoint maps that
to 409).
"""
from __future__ import annotations

import asyncio
import subprocess  # nosec B404
from typing import Any

import docker

from decnet.agent.topology_store import (
    AlreadyApplied,
    TopologyStore,
    observed,
)
from decnet.engine.deployer import (
    _compose,
    _compose_with_retry,
    _teardown_order,
    _topology_compose_path,
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


async def apply(
    hydrated: dict[str, Any],
    version_hash: str,
    store: TopologyStore,
) -> None:
    """Materialise *hydrated* on this agent and record it in *store*.

    Raises:
      HashMismatch: master and agent disagree on the canonical hash —
        don't touch docker, fail the apply.
      AlreadyApplied: a different topology is already applied here.
      ValidationError: topology fails structural validation.
      Any docker / compose error propagates up; the endpoint maps it
        to 500 and records the message on the store row.
    """
    local_hash = canonical_hash(hydrated)
    if local_hash != version_hash:
        raise HashMismatch(
            f"master hash {version_hash!r} does not match agent hash "
            f"{local_hash!r} — refusing to apply"
        )

    issues = _validate_topology(hydrated)
    if _validation_errors(issues):
        raise ValidationError(issues)

    topology_id = _topology_id(hydrated)
    # v1 guard: refuse cross-topology overwrite up-front.  Same check
    # lives in store.put() but we want a clean 409 path before we
    # start mutating docker state.
    existing = store.current()
    if existing is not None and existing.topology_id != topology_id:
        raise AlreadyApplied(
            f"agent already has topology {existing.topology_id!r}; "
            f"cannot apply {topology_id!r}"
        )

    lans = hydrated["lans"]
    compose_path = _topology_compose_path(topology_id)
    client = docker.from_env()

    # Bridges + compose are sync/blocking; hop to a thread so we don't
    # stall the event loop on a slow docker daemon.
    def _materialise() -> None:
        for lan in lans:
            net_name = _topology_network_name(topology_id, lan["name"])
            internal = not lan["is_dmz"]
            create_bridge_network(
                client, net_name, lan["subnet"], internal=internal
            )
        write_topology_compose(hydrated, compose_path)
        _compose_with_retry("up", "--build", "-d", compose_file=compose_path)

    await asyncio.to_thread(_materialise)

    store.put(topology_id, version_hash, hydrated)
    log.info(
        "topology %s applied on agent (%d LANs)", topology_id, len(lans)
    )


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
    client = docker.from_env()

    def _dismantle() -> None:
        if compose_path.exists():
            try:
                _compose("down", "--remove-orphans", compose_file=compose_path)
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
