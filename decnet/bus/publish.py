"""Fire-and-forget publish helpers shared across every worker.

Lifted out of ``decnet/mutator/engine.py`` once a second caller showed up
(DEBT-031).  Keeping one implementation means the "never break the worker
loop" guarantee is audited in exactly one place.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable

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
