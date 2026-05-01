"""Long-running credential-reuse correlator.

Loops :meth:`CorrelationEngine.correlate_credential_reuse` over the
credentials table and publishes ``credential.reuse.detected`` for every
new or grown ``CredentialReuse`` row. Mirrors the mutator's bus-wake +
slow-tick pattern from :mod:`decnet.mutator.engine`: woken on
``credential.captured`` and ``attacker.observed`` for sub-second latency,
falls back to a 60s poll if the bus is unavailable.
"""
from __future__ import annotations

import asyncio
import contextlib

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely,
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.correlation.engine import CorrelationEngine
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("correlation.reuse_worker")

_DEFAULT_POLL_SECS = 60.0
_DEFAULT_MIN_TARGETS = 2


async def run_reuse_loop(
    repo: BaseRepository,
    *,
    poll_interval_secs: float = _DEFAULT_POLL_SECS,
    min_targets: int = _DEFAULT_MIN_TARGETS,
    shutdown: asyncio.Event | None = None,
) -> None:
    """Run the credential-reuse correlator until cancelled.

    *shutdown* is an optional external stop signal; the loop also exits
    cleanly on ``CancelledError`` and ``KeyboardInterrupt``. The
    *min_targets* threshold is the minimum number of distinct
    ``(decky, service)`` pairs a secret must touch before it's persisted
    as a reuse finding.
    """
    log.info(
        "reuse correlator started poll_interval_secs=%s min_targets=%s",
        poll_interval_secs, min_targets,
    )

    bus: BaseBus | None = None
    wake = asyncio.Event()
    wake_tasks: list[asyncio.Task] = []
    heartbeat_task: asyncio.Task | None = None
    try:
        candidate = get_bus(client_name="reuse-correlator")
        await candidate.connect()
        bus = candidate
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, _topics.credential(_topics.CREDENTIAL_CAPTURED)),
        ))
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, _topics.attacker(_topics.ATTACKER_OBSERVED)),
        ))
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, "reuse-correlator"),
        )
        wake_tasks.append(asyncio.create_task(
            _run_control_listener_signal(bus, "reuse-correlator"),
        ))
    except Exception as exc:
        log.warning(
            "reuse correlator: bus unavailable, running in poll-only mode: %s",
            exc,
        )

    engine = CorrelationEngine()
    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        while not shutdown.is_set():
            try:
                results = await engine.correlate_credential_reuse(
                    repo, min_targets=min_targets,
                )
            except Exception:
                log.exception("reuse correlator: tick failed")
                results = []

            for row in results:
                await publish_safely(
                    bus,
                    _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED),
                    {
                        "id": row.get("id"),
                        "secret_kind": row.get("secret_kind"),
                        "target_count": row.get("target_count"),
                        "attacker_uuids": row.get("attacker_uuids"),
                        "attacker_ips": row.get("attacker_ips"),
                        "deckies": row.get("deckies"),
                        "services": row.get("services"),
                    },
                    event_type=_topics.CREDENTIAL_REUSE_DETECTED,
                )

            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=float(poll_interval_secs),
                )
            except asyncio.TimeoutError:
                pass
            wake.clear()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("reuse correlator stopped")
    finally:
        for t in wake_tasks:
            t.cancel()
        if heartbeat_task is not None:
            heartbeat_task.cancel()
        for task in (*wake_tasks, heartbeat_task):
            if task is None:
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _wake_on(bus: BaseBus, wake: asyncio.Event, pattern: str) -> None:
    """Flip *wake* every time *pattern* fires on the bus.

    Survives transient subscriber errors by logging and exiting; the
    poll-interval fallback keeps the loop alive in poll-only mode.
    """
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for _event in sub:
                wake.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.warning(
            "reuse correlator: subscriber for %s died (%s); falling back to poll",
            pattern, exc,
        )


__all__ = ["run_reuse_loop"]
