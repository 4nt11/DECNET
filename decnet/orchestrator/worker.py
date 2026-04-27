"""Orchestrator main loop.

One tick = one (src, dst, action) pick + one driver invocation + one DB
write + one fire-and-forget bus publish.  Intentionally serial — MVP
honesty: a wedged docker exec stalls only this worker, never another.

Modeled after :mod:`decnet.profiler.worker` for consistency: same control
listener, same heartbeat helper, same shutdown semantics.
"""
from __future__ import annotations

import asyncio
import contextlib

from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely,
    run_control_listener,
    run_health_heartbeat,
)
from decnet.logging import get_logger
from decnet.orchestrator import events, scheduler
from decnet.orchestrator.drivers import SSHDriver
from decnet.web.db.repository import BaseRepository

logger = get_logger("orchestrator")

# Periodic-prune knobs. Trim per-decky history every _PRUNE_EVERY_TICKS
# to keep orchestrator_events from unbounded growth on long-running
# fleets. Cheap on the write path (zero overhead per tick); the cost
# pays in once every ~100 ticks.
_PRUNE_EVERY_TICKS = 100
_PRUNE_PER_DST_CAP = 10000


async def orchestrator_worker(
    repo: BaseRepository,
    *,
    interval: int = 60,
) -> None:
    """Periodically inject synthetic activity into the running fleet.

    Runs as a long-lived asyncio task.  Honours the bus control topic
    (``system.orchestrator.control``) for graceful shutdown.
    """
    logger.info("orchestrator worker started interval=%ds", interval)

    bus = None
    try:
        bus = get_bus(client_name="orchestrator")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "orchestrator: bus unavailable, continuing without publish: %s", exc
        )
        bus = None

    driver = SSHDriver()
    shutdown = asyncio.Event()
    heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "orchestrator"))
    control_task = asyncio.create_task(
        run_control_listener(bus, "orchestrator", shutdown),
    )
    tick_n = 0
    try:
        while not shutdown.is_set():
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass  # normal tick
            if shutdown.is_set():
                break
            try:
                await _one_tick(repo, driver, bus)
            except Exception as exc:  # noqa: BLE001
                logger.error("orchestrator tick failed: %s", exc)
            tick_n += 1
            if tick_n % _PRUNE_EVERY_TICKS == 0:
                try:
                    deleted = await repo.prune_orchestrator_events(
                        per_dst_cap=_PRUNE_PER_DST_CAP,
                    )
                    if deleted:
                        logger.info(
                            "orchestrator prune deleted=%d cap=%d",
                            deleted, _PRUNE_PER_DST_CAP,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.error("orchestrator prune failed: %s", exc)
    finally:
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _one_tick(repo: BaseRepository, driver, bus) -> None:
    # Union view: MazeNET topology + unihost fleet + SWARM shards.  Pre-fleet
    # this only saw topology_deckies and was permanently blind to MACVLAN /
    # IPVLAN unihost decoys.
    deckies = await repo.list_running_deckies()
    action = scheduler.pick(deckies)
    if action is None:
        # Report the actual SSH-eligible count (what the scheduler filters
        # to), not just len(deckies) — the old "running+ssh count=N" line
        # reported the pre-filter count and misled debugging.
        ssh_eligible = sum(
            1 for d in deckies
            if isinstance(d.get("services"), list)
            and "ssh" in d["services"]
            and d.get("ip")
        )
        by_source: dict[str, int] = {}
        for d in deckies:
            by_source[d.get("source", "unknown")] = (
                by_source.get(d.get("source", "unknown"), 0) + 1
            )
        logger.debug(
            "orchestrator: no actionable deckies "
            "(running=%d ssh_eligible=%d sources=%s)",
            len(deckies), ssh_eligible, by_source,
        )
        return

    result = await driver.run(action)
    row = events.to_row(action, result)
    await repo.record_orchestrator_event(row)

    if bus is not None:
        topic = events.topic_for(action)
        # Bus payload mirrors the row but uses iso8601 for ts so SSE
        # consumers don't have to JSON-handle datetime themselves.
        bus_payload = {
            "kind": row["kind"],
            "protocol": row["protocol"],
            "action": row["action"],
            "src_decky_uuid": row.get("src_decky_uuid"),
            "dst_decky_uuid": row["dst_decky_uuid"],
            "success": row["success"],
            "payload": result.payload,
            "ts": row["ts"].isoformat(),
        }
        await publish_safely(
            bus, topic, bus_payload, event_type=events.event_type_for(action)
        )

    logger.info(
        "orchestrator tick kind=%s success=%s dst=%s",
        row["kind"], row["success"], row["dst_decky_uuid"],
    )
