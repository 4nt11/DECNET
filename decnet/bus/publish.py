"""Fire-and-forget publish helper shared across every worker.

Lifted out of ``decnet/mutator/engine.py`` once a second caller showed up
(DEBT-031).  Keeping one implementation means the "never break the worker
loop" guarantee is audited in exactly one place.
"""
from __future__ import annotations

from typing import Any

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
