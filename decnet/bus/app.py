# SPDX-License-Identifier: AGPL-3.0-or-later
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

Connect is **retried with a short backoff** (not one-shot): a startup
race where the API lifespan hits :func:`get_app_bus` before ``decnet
bus`` is ready would otherwise poison the singleton for the entire
process lifetime.  Instead we remember the last failure timestamp and
let callers retry once ``_RETRY_BACKOFF`` seconds have passed.
"""
from __future__ import annotations

import asyncio
import time

from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.logging import get_logger

log = get_logger("bus.app")

# Publishers in the hot path shouldn't pay connect-retry latency on every
# call; the dashboard's own 5 s poll interval recovers within one tick
# once the bus comes up.  A persistently-dead bus only gets a connect
# attempt every 2 s, not once per request.
_RETRY_BACKOFF: float = 2.0

_lock = asyncio.Lock()
_shared: BaseBus | None = None
_last_failure_ts: float = 0.0


async def get_app_bus() -> BaseBus | None:
    """Return the process-wide connected bus, or ``None`` if unavailable.

    On first call, constructs a client via :func:`get_bus` and awaits
    ``connect()``.  Subsequent calls return the cached instance.  If a
    connect attempt raises, the failure timestamp is recorded and
    subsequent calls within ``_RETRY_BACKOFF`` seconds return ``None``
    without re-attempting — after the backoff window, the next call
    retries.  This is what lets the API recover from a
    ``decnet bus``-started-after-API race without a full API restart.
    """
    global _shared, _last_failure_ts
    if _shared is not None:
        return _shared
    if (time.monotonic() - _last_failure_ts) < _RETRY_BACKOFF:
        return None
    async with _lock:
        if _shared is not None:
            return _shared
        if (time.monotonic() - _last_failure_ts) < _RETRY_BACKOFF:
            return None
        try:
            candidate = get_bus(client_name="api")
            await candidate.connect()
            _shared = candidate
            _last_failure_ts = 0.0
            return _shared
        except Exception as exc:  # noqa: BLE001
            log.warning("app bus unavailable: %s", exc)
            _last_failure_ts = time.monotonic()
            return None


async def close_app_bus() -> None:
    """Close the shared bus if one is open; clear the backoff window.

    Call from the API lifespan shutdown.  Safe to call multiple times.
    Resetting ``_last_failure_ts`` means the next ``get_app_bus()``
    after shutdown-and-restart-within-the-same-process (rare, but
    tests do this) retries immediately instead of honouring a stale
    backoff.
    """
    global _shared, _last_failure_ts
    bus, _shared = _shared, None
    _last_failure_ts = 0.0
    if bus is not None:
        try:
            await bus.close()
        except Exception as exc:  # noqa: BLE001
            log.warning("app bus close raised: %s", exc)
