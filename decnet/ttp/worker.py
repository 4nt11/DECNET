"""Long-running TTP-tagging worker.

Contract step E.1.7 of ``development/TTP_TAGGING.md``. Bus loop only:
connects, subscribes to the documented topics, runs heartbeat +
control listener, idles on the wake event. Real evaluation,
publishing, and persistence land in E.3 — the lifecycle wiring here
mirrors :mod:`decnet.intel.worker` and :mod:`decnet.clustering.worker`
exactly so the impl phase only fills in the inner loop.

Bus subscriptions are enumerated as the module-level constant
:data:`_TOPICS` so E.2.12 can assert subscription wiring without
invoking the loop. The constant is the *single source of truth* — the
loop iterates over it; tests introspect it. Drift between code and
spec becomes a failed equality check, not a silent regression.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Optional

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.logging import get_logger
from decnet.ttp.base import Tagger
from decnet.ttp.factory import get_tagger
from decnet.web.db.repository import BaseRepository

log = get_logger("ttp.worker")

_DEFAULT_POLL_SECS = 60.0


# Bus topics the worker subscribes to. Kept as a module-level constant
# so E.2.12 can assert subscription wiring without invoking the loop —
# the test introspects this tuple, the loop iterates it. The set
# matches the design doc "Worker shape" section: session-ended primary
# trigger, observed for low-latency rules, intel-enriched + identity
# events for opportunistic re-tag, credential-reuse + email for the
# dedicated lifters, and ``canary.>`` for fleet-wide canary triggers.
_TOPICS: tuple[str, ...] = (
    _topics.attacker(_topics.ATTACKER_SESSION_ENDED),
    _topics.attacker(_topics.ATTACKER_OBSERVED),
    _topics.attacker(_topics.ATTACKER_INTEL_ENRICHED),
    _topics.identity(_topics.IDENTITY_FORMED),
    _topics.identity(_topics.IDENTITY_MERGED),
    _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED),
    _topics.email_topic(_topics.EMAIL_RECEIVED),
    # Canary triggers carry a per-token segment, so subscribe with the
    # multi-token wildcard rather than enumerating per-token. Pattern
    # validated against ``decnet.bus.topics.canary()``'s shape.
    f"{_topics.CANARY}.>",
)


async def run_ttp_worker_loop(
    repo: BaseRepository,
    *,
    poll_interval_secs: float = _DEFAULT_POLL_SECS,
    tagger: Optional[Tagger] = None,
    shutdown: Optional[asyncio.Event] = None,
) -> None:
    """Run the TTP-tagging loop until cancelled.

    *tagger* defaults to :func:`decnet.ttp.factory.get_tagger` — tests
    pass a fake. *shutdown* is an optional external stop signal; the
    loop also exits cleanly on :class:`asyncio.CancelledError` and
    :class:`KeyboardInterrupt`.

    Contract phase: the inner loop is a no-op idle. Bus connect,
    heartbeat, control-listener, and topic subscriptions are wired so
    the worker registers as ``ttp`` in
    :data:`decnet.web.worker_registry.KNOWN_WORKERS` from day one. E.3
    fills in evaluation, persistence, and ``ttp.tagged`` publishes.
    """
    if tagger is None:
        tagger = get_tagger()
    log.info(
        "ttp worker started tagger=%s poll_interval_secs=%s topics=%d",
        tagger.name, poll_interval_secs, len(_TOPICS),
    )

    bus: Optional[BaseBus] = None
    wake = asyncio.Event()
    wake_tasks: list[asyncio.Task] = []
    heartbeat_task: Optional[asyncio.Task] = None
    try:
        candidate = get_bus(client_name="ttp")
        await candidate.connect()
        bus = candidate
        for pattern in _TOPICS:
            wake_tasks.append(asyncio.create_task(
                _wake_on(bus, wake, pattern),
            ))
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, "ttp"),
        )
        wake_tasks.append(asyncio.create_task(
            _run_control_listener_signal(bus, "ttp"),
        ))
    except Exception as exc:  # noqa: BLE001
        # Bus-unavailable is the steady state on dev boxes without a
        # NATS daemon — fall back to poll-only so the worker still
        # registers and the impl phase can backfill.
        log.warning(
            "ttp worker: bus unavailable, running in poll-only mode: %s", exc,
        )

    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        while not shutdown.is_set():
            # Contract phase: the actual evaluate + insert + publish
            # work lives in E.3. The shell idles on wake / poll so the
            # heartbeat keeps reporting and the control listener can
            # cleanly stop us.
            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=float(poll_interval_secs),
                )
            except asyncio.TimeoutError:
                pass
            wake.clear()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("ttp worker stopped")
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
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "ttp worker: subscriber for %s died (%s); falling back to poll",
            pattern, exc,
        )


__all__ = ["run_ttp_worker_loop", "_TOPICS"]
