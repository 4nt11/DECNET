"""Process-wide bus singleton for request-serving workers (API, SSE routes).

A single connected :class:`~decnet.bus.base.BaseBus` shared across request
handlers — opening a UNIX socket per request would be wasteful and add
latency to the hot path.  The API lifespan is responsible for calling
:func:`close_app_bus` on shutdown; connect is lazy so tests and
contract-test mode that never hit a publish/subscribe code path don't
pay for a bus connection they'll never use.

Failures during :meth:`BaseBus.connect` are swallowed and logged — a
dead bus must never break request serving.  Publishers should treat a
``None`` return from :func:`get_app_bus` as "skip this notification",
same as ``DECNET_BUS_ENABLED=false``.
"""
from __future__ import annotations

import asyncio

from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.logging import get_logger

log = get_logger("bus.app")

_lock = asyncio.Lock()
_shared: BaseBus | None = None
_tried = False


async def get_app_bus() -> BaseBus | None:
    """Return the process-wide connected bus, or ``None`` if unavailable.

    On first call, constructs a client via :func:`get_bus` and awaits
    ``connect()``.  Subsequent calls return the cached instance.  If the
    initial connect raises, we remember the failure and return ``None``
    from here on — callers are expected to fall back cleanly.
    """
    global _shared, _tried
    if _shared is not None:
        return _shared
    if _tried:
        return None
    async with _lock:
        if _shared is not None:
            return _shared
        if _tried:
            return None
        _tried = True
        try:
            candidate = get_bus(client_name="api")
            await candidate.connect()
            _shared = candidate
        except Exception as exc:  # noqa: BLE001
            log.warning("app bus unavailable: %s", exc)
            return None
    return _shared


async def close_app_bus() -> None:
    """Close the shared bus if one is open; reset the tried-once guard.

    Call from the API lifespan shutdown.  Safe to call multiple times.
    """
    global _shared, _tried
    bus, _shared = _shared, None
    _tried = False
    if bus is not None:
        try:
            await bus.close()
        except Exception as exc:  # noqa: BLE001
            log.warning("app bus close raised: %s", exc)
