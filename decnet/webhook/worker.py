"""Webhook dispatcher — bus consumer → HTTP egress.

Spawns one asyncio task per (subscription, pattern) pair. Each task
subscribes to the bus, iterates matching events, and POSTs them via
`decnet.webhook.client.deliver`. Reloads on `WEBHOOK_SUBSCRIPTIONS_CHANGED`
bus signals and as a slow fallback so a dropped signal costs latency,
not correctness.

One-task-per-pair is deliberately dumb: cancellation propagates cleanly,
and the bus's own trie does the actual pattern matching — no in-memory
filter logic to maintain. Scales fine up to thousands of subs; if that
ever breaks down we collapse to one task per distinct pattern and add
in-memory dispatch.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from decnet.bus.factory import get_bus
from decnet.bus.publish import run_control_listener, run_health_heartbeat
from decnet.bus import topics as _topics
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository
from decnet.webhook.client import deliver

logger = get_logger("webhook_worker")


_RELOAD_FALLBACK_SECS = 60.0
# Max parallel HTTP egress — one global semaphore keeps the process's
# outbound footprint bounded regardless of event volume.
_EGRESS_CONCURRENCY = 10
# Circuit-breaker trip point. After this many consecutive delivery
# failures the worker auto-disables the subscription so one dead
# receiver can't poison the shared egress pool. Override via
# DECNET_WEBHOOK_CIRCUIT_THRESHOLD. Operator clears the trip by
# toggling `enabled` back on via PATCH.
_CIRCUIT_THRESHOLD = max(1, int(os.environ.get("DECNET_WEBHOOK_CIRCUIT_THRESHOLD", "5")))


def _patterns_for(sub: dict[str, Any]) -> list[str]:
    raw = sub.get("topic_patterns") or "[]"
    try:
        return [p for p in json.loads(raw) if isinstance(p, str)]
    except (ValueError, TypeError):
        return []


def _union_patterns(subs: list[dict[str, Any]]) -> list[str]:
    """Dedup patterns across all subs, preserving first-occurrence order."""
    seen: set[str] = set()
    out: list[str] = []
    for sub in subs:
        for p in _patterns_for(sub):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


async def webhook_worker(
    repo: BaseRepository,
    *,
    reload_interval: float = _RELOAD_FALLBACK_SECS,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """Main entry — connect bus, spawn per-subscription delivery tasks,
    reload on signal."""
    logger.info("webhook worker started")

    bus = None
    try:
        bus = get_bus(client_name="webhook")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001 — bus is optional (DEBT-031)
        logger.warning("webhook: bus unavailable, running in idle mode: %s", exc)
        bus = None

    shutdown = asyncio.Event()
    reload_flag = asyncio.Event()

    heartbeat_task = (
        asyncio.create_task(run_health_heartbeat(bus, "webhook"))
        if bus is not None else None
    )
    control_task = (
        asyncio.create_task(run_control_listener(bus, "webhook", shutdown))
        if bus is not None else None
    )
    reload_task = (
        asyncio.create_task(_reload_listener(bus, reload_flag, shutdown))
        if bus is not None else None
    )

    owns_http = http_client is None
    if owns_http:
        http_client = httpx.AsyncClient(timeout=10.0)

    semaphore = asyncio.Semaphore(_EGRESS_CONCURRENCY)
    consumer_tasks: list[asyncio.Task] = []

    try:
        while not shutdown.is_set():
            # Cancel prior epoch's consumers before starting new ones.
            await _cancel_all(consumer_tasks)
            consumer_tasks.clear()

            subs = await repo.list_webhook_subscriptions(enabled_only=True)

            if bus is not None:
                for sub in subs:
                    for pattern in _patterns_for(sub):
                        consumer_tasks.append(asyncio.create_task(
                            _consume(
                                bus, pattern, sub, repo, http_client, semaphore, reload_flag,
                            )
                        ))

            # Wait for reload OR timer fallback. Shutdown propagates via
            # CancelledError when the outer task is cancelled — no explicit
            # race required because `await` points are cancellation-safe.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    reload_flag.wait(), timeout=reload_interval
                )
            reload_flag.clear()
    except asyncio.CancelledError:
        shutdown.set()
        raise
    finally:
        await _cancel_all(consumer_tasks)
        for t in (heartbeat_task, control_task, reload_task):
            if t is not None:
                t.cancel()
        for t in (heartbeat_task, control_task, reload_task):
            if t is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()
        if owns_http and http_client is not None:
            await http_client.aclose()


async def _cancel_all(tasks: list[asyncio.Task]) -> None:
    for t in tasks:
        if not t.done():
            t.cancel()
    for t in tasks:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await t


async def _consume(
    bus,
    pattern: str,
    sub: dict[str, Any],
    repo: BaseRepository,
    http_client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    reload_flag: asyncio.Event,
) -> None:
    """Subscribe to one pattern and dispatch events to one webhook."""
    try:
        subscription = bus.subscribe(pattern)
        async with subscription:
            async for event in subscription:
                asyncio.create_task(
                    _dispatch_one(repo, http_client, semaphore, sub, event, reload_flag)
                )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(
            "webhook: consumer crashed sub=%s pattern=%s err=%s",
            sub.get("name"), pattern, exc,
        )


async def _dispatch_one(
    repo: BaseRepository,
    http_client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    sub: dict[str, Any],
    event: Any,
    reload_flag: asyncio.Event,
) -> None:
    async with semaphore:
        try:
            result = await deliver(sub, event, client=http_client)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "webhook: deliver raised for sub=%s topic=%s: %s",
                sub.get("uuid"), getattr(event, "topic", ""), exc,
            )
            await _safe_record_failure(
                repo, sub["uuid"], f"internal: {exc}", sub.get("name", ""), reload_flag,
            )
            return

        now = datetime.now(timezone.utc)
        if result.ok:
            await _safe_record_success(repo, sub["uuid"], now)
        else:
            logger.warning(
                "webhook: delivery failed sub=%s topic=%s status=%s err=%s",
                sub.get("name"), getattr(event, "topic", ""),
                result.status_code, result.error,
            )
            await _safe_record_failure(
                repo, sub["uuid"], result.error or "unknown", sub.get("name", ""), reload_flag,
            )


async def _safe_record_success(
    repo: BaseRepository, uuid: str, ts: datetime
) -> None:
    try:
        await repo.record_webhook_success(uuid, ts)
    except Exception as exc:
        logger.warning("webhook: record_success failed: %s", exc)


async def _safe_record_failure(
    repo: BaseRepository,
    uuid: str,
    error: str,
    sub_name: str = "",
    reload_flag: asyncio.Event | None = None,
) -> None:
    try:
        now = datetime.now(timezone.utc)
        new_count = await repo.record_webhook_failure(uuid, now, error)
    except Exception as exc:
        logger.warning("webhook: record_failure failed: %s", exc)
        return

    # Circuit breaker — trip after threshold. Set the reload flag so the
    # outer loop re-queries the DB and stops consuming events for the
    # now-disabled sub. Idempotent: tripping an already-tripped sub just
    # re-stamps auto_disabled_at.
    if new_count >= _CIRCUIT_THRESHOLD:
        try:
            await repo.trip_webhook_circuit(uuid, now)
            logger.warning(
                "webhook: circuit tripped sub=%s uuid=%s failures=%d threshold=%d",
                sub_name or "<unknown>", uuid, new_count, _CIRCUIT_THRESHOLD,
            )
            if reload_flag is not None:
                reload_flag.set()
        except Exception as exc:
            logger.warning("webhook: trip_circuit failed: %s", exc)


async def _reload_listener(
    bus, reload_flag: asyncio.Event, shutdown: asyncio.Event
) -> None:
    """Set `reload_flag` on every WEBHOOK_SUBSCRIPTIONS_CHANGED signal."""
    try:
        sub = bus.subscribe(_topics.WEBHOOK_SUBSCRIPTIONS_CHANGED)
        async with sub:
            async for _event in sub:
                if shutdown.is_set():
                    return
                reload_flag.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(
            "webhook: reload listener crashed, fallback timer only: %s", exc
        )
