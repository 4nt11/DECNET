"""Fire-and-forget publish helpers shared across every worker.

Lifted out of ``decnet/mutator/engine.py`` once a second caller showed up
(DEBT-031).  Keeping one implementation means the "never break the worker
loop" guarantee is audited in exactly one place.
"""
from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any, Callable

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.logging import get_logger

log = get_logger("bus.publish")


async def publish_safely(
    bus: BaseBus | None,
    topic: str,
    payload: dict[str, Any],
    event_type: str = "",
) -> None:
    """Publish on *bus* without ever raising back at the caller.

    The DB row (or equivalent side-effect) has already been committed by
    the time a worker calls this; the bus is the notification layer, not
    the source of truth.  A dropped publish is at most a few seconds of
    UI latency until the next poll tick.  A raised exception here, by
    contrast, would crash the worker — which is strictly worse.
    """
    if bus is None:
        return
    try:
        await bus.publish(topic, payload, event_type=event_type)
    except Exception as exc:  # noqa: BLE001
        log.warning("bus publish failed topic=%s: %s", topic, exc)


def make_thread_safe_publisher(
    bus: BaseBus | None,
    loop: asyncio.AbstractEventLoop,
) -> Callable[[str, dict[str, Any], str], None]:
    """Build a sync callable that marshals publishes back to *loop*.

    Workers that run their hot paths in a worker thread (scapy sniff loop,
    ``asyncio.to_thread`` probes, blocking socket reads) cannot ``await``
    the bus directly.  This helper returns a plain function that schedules
    the publish on *loop* via ``run_coroutine_threadsafe`` and returns
    immediately — the calling thread is never blocked on the publish.

    A ``None`` bus yields a no-op callable, matching the degraded-mode
    contract the rest of this module already upholds.
    """
    if bus is None:
        return lambda _topic, _payload, _event_type="": None

    def _publish(topic: str, payload: dict[str, Any], event_type: str = "") -> None:
        try:
            asyncio.run_coroutine_threadsafe(
                publish_safely(bus, topic, payload, event_type=event_type),
                loop,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("cross-thread bus publish failed topic=%s: %s", topic, exc)

    return _publish


async def run_health_heartbeat(
    bus: BaseBus | None,
    worker: str,
    *,
    interval: float = 30.0,
    extra: Callable[[], dict[str, Any]] | None = None,
) -> None:
    """Publish ``system.<worker>.health`` every *interval* seconds.

    Standard heartbeat loop shared across agent/forwarder/updater.  Emits
    ``{"worker": <name>, "ts": <unix-ts>, **extra()}`` on each tick.  A
    ``None`` bus turns the loop into a no-op sleep cycle — still cancellable
    so the caller can use the same ``asyncio.create_task``/``.cancel()``
    pattern regardless of bus state.

    Cancellation-safe: unwraps the ``CancelledError`` so callers awaiting
    the task during shutdown see a clean exit.
    """
    topic = _topics.system_health(worker)
    with contextlib.suppress(asyncio.CancelledError):
        while True:
            payload: dict[str, Any] = {"worker": worker, "ts": time.time()}
            if extra is not None:
                try:
                    payload.update(extra())
                except Exception as exc:  # noqa: BLE001
                    log.debug("heartbeat extra() failed worker=%s: %s", worker, exc)
            await publish_safely(bus, topic, payload, event_type=_topics.SYSTEM_HEALTH)
            await asyncio.sleep(interval)
