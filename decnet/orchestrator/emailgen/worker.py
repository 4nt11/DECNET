"""Emailgen main loop.

Mirrors :mod:`decnet.orchestrator.worker` shape: same heartbeat, same
control listener, same fire-and-forget bus publish, same prune knob.
A wedged ollama call stalls only this worker, never the SSH-flavoured
orchestrator running alongside.
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
from decnet.orchestrator.drivers.email import EmailDriver
from decnet.orchestrator.emailgen import events, scheduler
from decnet.web.db.repository import BaseRepository

logger = get_logger("orchestrator.emailgen")

# Periodic-prune knobs — same shape as orchestrator/worker.py.
_PRUNE_EVERY_TICKS = 100
_PRUNE_PER_DECKY_CAP = 5000


async def emailgen_worker(
    repo: BaseRepository,
    *,
    interval: int = 300,
    model: str | None = None,
) -> None:
    """Periodically generate one fake email into a running mail decky.

    Default interval is 5 minutes — emails are expensive (LLM round
    trip) and don't need to fire every minute to look natural.  Honors
    ``system.emailgen.control`` for graceful shutdown.
    """
    logger.info("emailgen worker started interval=%ds model=%s", interval, model)

    bus = None
    try:
        bus = get_bus(client_name="emailgen")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "emailgen: bus unavailable, continuing without publish: %s", exc
        )
        bus = None

    driver = EmailDriver(model=model) if model else EmailDriver()
    shutdown = asyncio.Event()
    heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "emailgen"))
    control_task = asyncio.create_task(
        run_control_listener(bus, "emailgen", shutdown),
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
                logger.error("emailgen tick failed: %s", exc)
            tick_n += 1
            if tick_n % _PRUNE_EVERY_TICKS == 0:
                try:
                    deleted = await repo.prune_orchestrator_emails(
                        per_decky_cap=_PRUNE_PER_DECKY_CAP,
                    )
                    if deleted:
                        logger.info(
                            "emailgen prune deleted=%d cap=%d",
                            deleted, _PRUNE_PER_DECKY_CAP,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.error("emailgen prune failed: %s", exc)
    finally:
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _one_tick(repo: BaseRepository, driver: EmailDriver, bus) -> None:
    action = await scheduler.pick(repo)
    if action is None:
        logger.debug("emailgen: no actionable mail decky / personas this tick")
        return

    result = await driver.run(action)
    row = events.to_row(action, result)
    await repo.record_orchestrator_email(row)

    if bus is not None:
        topic = events.topic_for(action)
        # Mirror the orchestrator-event SSE-friendly payload shape: ts
        # as iso8601, payload as already-serialised dict.
        bus_payload = {
            "kind": "email",
            "mail_decky_uuid": row["mail_decky_uuid"],
            "thread_id": row["thread_id"],
            "message_id": row["message_id"],
            "in_reply_to": row["in_reply_to"],
            "sender_email": row["sender_email"],
            "recipient_email": row["recipient_email"],
            "subject": row["subject"],
            "language": row["language"],
            "success": row["success"],
            "ts": row["ts"].isoformat(),
        }
        await publish_safely(
            bus, topic, bus_payload, event_type=events.event_type_for(action),
        )

    logger.info(
        "emailgen tick mail_decky=%s thread=%s success=%s reply=%s",
        row["mail_decky_uuid"], row["thread_id"], row["success"], action.is_reply,
    )
