# SPDX-License-Identifier: AGPL-3.0-or-later
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

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.publish import publish_safely
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
    bus: Optional[BaseBus] = None,
) -> dict[str, int]:
    """Single reconciliation pass.  Returns counts of work done.

    When *bus* is provided, fires ``decky.<host_uuid:name>.state`` on every
    insert / delete / state transition.  The DB write is the source of
    truth — bus publish is best-effort notification; a dropped event is at
    most one tick of UI latency.
    """
    counts = {"inserted": 0, "deleted": 0, "state_updated": 0}

    state = await asyncio.to_thread(load_state_fn)
    json_deckies: list[Any] = list(state[0].deckies) if state else []

    db_rows = await repo.list_fleet_deckies(host_uuid=host_uuid)
    db_by_name = {r["name"]: r for r in db_rows}

    container_states = await asyncio.to_thread(
        _collect_container_states, docker_client_factory,
    )
    json_names = {d.name for d in json_deckies}

    # 1. INSERT: present in JSON, absent from DB.
    for d in json_deckies:
        if d.name in db_by_name:
            continue
        new_state = (
            _aggregate_decky_state(d.name, list(d.services), container_states)
            if container_states is not None else "running"
        )
        row_host = d.host_uuid or host_uuid
        await repo.upsert_fleet_decky({
            "host_uuid": row_host,
            "name": d.name,
            "services": list(d.services),
            "decky_config": d.model_dump(mode="json"),
            "decky_ip": d.ip,
            "state": new_state,
        })
        counts["inserted"] += 1
        await _emit_state(bus, row_host, d.name, new_state, transition="inserted")

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
            await _emit_state(
                bus, r["host_uuid"], r["name"], "torn_down",
                transition="deleted",
            )

    # 3. STATE: present in both, docker says something fresh.
    if container_states is not None:
        for d in json_deckies:
            existing = db_by_name.get(d.name)
            if existing is None:
                continue  # already handled in step 1
            new_state = _aggregate_decky_state(
                d.name, list(d.services), container_states,
            )
            previous_state = existing.get("state")
            if previous_state != new_state:
                await repo.update_fleet_decky_state(
                    host_uuid=existing["host_uuid"],
                    name=d.name,
                    state=new_state,
                )
                counts["state_updated"] += 1
                await _emit_state(
                    bus, existing["host_uuid"], d.name, new_state,
                    transition="state_changed",
                    previous=previous_state,
                )

    return counts


async def _emit_state(
    bus: Optional[BaseBus],
    host_uuid: str,
    name: str,
    state: str,
    *,
    transition: str,
    previous: Optional[str] = None,
) -> None:
    """Publish ``decky.<host_uuid:name>.state`` on a fleet row transition.

    Topic uses an existing topic family (``DECKY_STATE``) — no
    bus/topics.py change required.  The composite ``host_uuid:name`` keeps
    fleet rows distinguishable from MazeNET TopologyDecky rows (whose ids
    are bare UUIDs).  A ``:`` is a legal token character; ``.``, ``*``,
    ``>``, and whitespace are the only banned ones (see
    ``bus.topics._reject_tokens``).
    """
    if bus is None:
        return
    decky_id = f"{host_uuid}:{name}"
    payload: dict[str, Any] = {
        "host_uuid": host_uuid,
        "name": name,
        "state": state,
        "transition": transition,
        "source": "fleet",
    }
    if previous is not None:
        payload["previous_state"] = previous
    await publish_safely(
        bus,
        _topics.decky(decky_id, _topics.DECKY_STATE),
        payload,
        event_type=_topics.DECKY_STATE,
    )
