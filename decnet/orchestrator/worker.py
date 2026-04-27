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
    import secrets as _secrets

    # Union view: MazeNET topology + unihost fleet + SWARM shards.  Pre-fleet
    # this only saw topology_deckies and was permanently blind to MACVLAN /
    # IPVLAN unihost decoys.
    deckies = await repo.list_running_deckies()
    rng = _secrets.SystemRandom()

    # Action-kind roll: 50/50 traffic vs file.  Stage 5 of the realism
    # migration adds an email branch (when emailgen folds in).  When a
    # roll yields nothing actionable (e.g. file branch with no personas
    # in any persona's work hours), we fall through to the other side
    # so a quiet half doesn't silence the whole tick.
    action = None
    if rng.random() < 0.5:
        action = scheduler.pick(deckies, rand=rng)
        if action is None:
            action = await scheduler.pick_file(deckies, repo, rand=rng)
    else:
        action = await scheduler.pick_file(deckies, repo, rand=rng)
        if action is None:
            action = scheduler.pick(deckies, rand=rng)

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
    # Persist realism state for FileAction so stage 3b's edit-in-place
    # has something to read back.  Failure here is logged but doesn't
    # tank the tick — the orchestrator event is the source of truth
    # for "this action happened."
    if isinstance(action, scheduler.FileAction) and result.success:
        try:
            await _record_synthetic_file(repo, action, result)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "orchestrator: synthetic_files write failed dst=%s path=%s: %s",
                action.dst_uuid, action.path, exc,
            )

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


async def _record_synthetic_file(repo, action, result) -> None:
    """Persist a synthetic_files row after a successful FileAction plant.

    Idempotent on ``(decky_uuid, path)``: when the unique constraint
    fires (the file existed already), we instead patch the existing
    row's ``last_modified`` / ``content_hash`` / ``last_body`` / bump
    ``edit_count`` so the dashboard's "files this decky has grown"
    view stays accurate even when the orchestrator re-plants the same
    location.
    """
    import hashlib
    from datetime import datetime, timezone

    body = action.content or ""
    content_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    row = {
        "decky_uuid": action.dst_uuid,
        "path": action.path,
        "persona": action.persona,
        "content_class": action.content_class,
        "created_at": now,
        "last_modified": now,
        "edit_count": 0,
        "content_hash": content_hash,
        # Cap the persisted body — large blobs (DOCX/PDF/canary
        # artifacts in stage 7) are wasted disk on this side; the
        # decky filesystem holds the canonical bytes.
        "last_body": body[:65536],
    }
    try:
        await repo.record_synthetic_file(row)
    except Exception:  # noqa: BLE001
        # Most likely the unique constraint on (decky_uuid, path)
        # fired — flip to update mode by looking up the existing row.
        existing = await repo.list_synthetic_files(
            decky_uuid=action.dst_uuid, limit=200,
        )
        match = next(
            (r for r in existing if r.get("path") == action.path), None,
        )
        if match is None:
            raise
        await repo.update_synthetic_file(
            match["uuid"],
            {
                "last_modified": now,
                "content_hash": content_hash,
                "last_body": body[:65536],
                "edit_count": int(match.get("edit_count", 0)) + 1,
            },
        )
