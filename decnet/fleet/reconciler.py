"""Fleet reconciler — converges JSON ↔ DB ↔ docker.

Three sources of truth on a DECNET host can disagree:

1. ``decnet-state.json`` — written by ``engine.deployer.deploy/teardown``;
   the canonical record for offline / no-API consumers (``decnet status``,
   ``decnet teardown``, sniffer, collector).
2. ``fleet_deckies`` table — DB mirror written by the same deployer; what
   the orchestrator, web dashboard, and REST API see.
3. ``docker inspect`` — actual per-container runtime state.

Drift sources we accept and correct:

* CLI deploy on a host whose DB was unreachable → JSON ahead of DB.
* CLI teardown on a host whose DB was unreachable → DB ahead of JSON.
* Operator hand-edited ``decnet-state.json`` → JSON ahead of DB.
* Container crashed / was killed externally → DB state stale until docker
  is observed.

Resolution:

* JSON has X, DB doesn't → INSERT.
* DB has X (this host), JSON doesn't → DELETE.
* Both have X → state := docker-aggregated state.

Cross-host safety: deletions are scoped to ``host_uuid == this host``.
A multi-host master that runs swarm workers (each with their own
reconciler) must never delete a peer's rows.

The reconciler intentionally does NOT publish bus events for state
changes today — the dashboard reads the DB on every render.  A
``fleet.{name}.state`` topic is a natural follow-up if SSE consumers
appear, but is out of scope for this PR.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from decnet.config import DecnetConfig, load_state as _real_load_state
from decnet.logging import get_logger
from decnet.web.db.models import LOCAL_HOST_SENTINEL
from decnet.web.db.repository import BaseRepository

logger = get_logger("fleet.reconciler")


# ── docker observation ────────────────────────────────────────────────────────

def _collect_container_states(
    docker_client_factory: Optional[Callable[[], Any]] = None,
) -> Optional[dict[str, str]]:
    """Return ``{container_name: status}`` or ``None`` if docker is unreachable.

    ``None`` is the explicit "unknown" signal — callers must NOT treat
    docker failure as "every container is gone" (that would torch every
    fleet row to ``torn_down`` whenever the docker socket is busy).
    """
    if docker_client_factory is None:
        try:
            import docker  # local import — keeps tests import-clean
            docker_client_factory = docker.from_env
        except ImportError:
            return None
    try:
        client = docker_client_factory()
        return {
            c.name: c.status
            for c in client.containers.list(all=True, ignore_removed=True)
        }
    except Exception as exc:  # noqa: BLE001
        logger.debug("reconciler: docker query failed: %s", exc)
        return None


def _aggregate_decky_state(
    decky_name: str,
    services: list[str],
    container_states: dict[str, str],
) -> str:
    """Aggregate per-decky state from per-service container statuses.

    ``running``    — every expected service container is ``running``.
    ``failed``     — every observed container is non-running.
    ``degraded``   — partial: some running, some not (or some missing).
    ``torn_down``  — no expected container observed at all.
    """
    expected = {f"{decky_name}-{svc.replace('_', '-')}" for svc in services}
    seen = {n: s for n, s in container_states.items() if n in expected}
    if not seen:
        return "torn_down"
    statuses = set(seen.values())
    if statuses == {"running"} and len(seen) == len(expected):
        return "running"
    if "running" not in statuses:
        return "failed"
    return "degraded"


# ── reconcile pass ────────────────────────────────────────────────────────────

async def reconcile_once(
    repo: BaseRepository,
    *,
    host_uuid: str = LOCAL_HOST_SENTINEL,
    load_state_fn: Callable[[], Optional[tuple[DecnetConfig, Any]]] = _real_load_state,
    docker_client_factory: Optional[Callable[[], Any]] = None,
) -> dict[str, int]:
    """Single reconciliation pass.  Returns counts of work done."""
    counts = {"inserted": 0, "deleted": 0, "state_updated": 0}

    state = await asyncio.to_thread(load_state_fn)
    json_deckies: list[Any] = list(state[0].deckies) if state else []

    db_rows = await repo.list_fleet_deckies(host_uuid=host_uuid)
    db_by_name = {r["name"]: r for r in db_rows}

    container_states = await asyncio.to_thread(
        _collect_container_states, docker_client_factory,
    )
    docker_known = container_states is not None

    json_names = {d.name for d in json_deckies}

    # 1. INSERT: present in JSON, absent from DB.
    for d in json_deckies:
        if d.name in db_by_name:
            continue
        new_state = (
            _aggregate_decky_state(d.name, list(d.services), container_states)
            if docker_known else "running"
        )
        await repo.upsert_fleet_decky({
            "host_uuid": d.host_uuid or host_uuid,
            "name": d.name,
            "services": list(d.services),
            "decky_config": d.model_dump(mode="json"),
            "decky_ip": d.ip,
            "state": new_state,
        })
        counts["inserted"] += 1

    # 2. DELETE: present in DB (this host), absent from JSON.
    # Scoped to host_uuid by list_fleet_deckies(host_uuid=...) call above —
    # peer-host rows are never visible here, so we can't accidentally
    # clobber another worker's slice.
    for r in db_rows:
        if r["name"] not in json_names:
            await repo.delete_fleet_decky(
                host_uuid=r["host_uuid"], name=r["name"],
            )
            counts["deleted"] += 1

    # 3. STATE: present in both, docker says something fresh.
    if docker_known:
        for d in json_deckies:
            existing = db_by_name.get(d.name)
            if existing is None:
                continue  # already handled in step 1
            new_state = _aggregate_decky_state(
                d.name, list(d.services), container_states,
            )
            if existing.get("state") != new_state:
                await repo.update_fleet_decky_state(
                    host_uuid=existing["host_uuid"],
                    name=d.name,
                    state=new_state,
                )
                counts["state_updated"] += 1

    return counts
