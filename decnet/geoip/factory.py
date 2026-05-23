# SPDX-License-Identifier: AGPL-3.0-or-later
"""GeoIP provider factory.

Dispatch key: ``DECNET_GEOIP_PROVIDER`` (default ``rir``). Lazy singleton,
same shape as :func:`decnet.bus.factory.get_bus`.

MVP wires only the RIR provider. ``dbip`` and ``maxmind`` slots are
reserved and raise :class:`NotImplementedError` until their subpackages
land.
"""
from __future__ import annotations

import os
from typing import Optional

from decnet.geoip.base import Provider

_cached: Optional[Provider] = None
_cached_key: Optional[str] = None


def get_provider() -> Provider:
    """Return the configured :class:`Provider` singleton."""
    global _cached, _cached_key
    key = os.environ.get("DECNET_GEOIP_PROVIDER", "rir").lower()
    if _cached is not None and _cached_key == key:
        return _cached

    if key == "rir":
        from decnet.geoip.rir.provider import RirProvider
        provider: Provider = RirProvider()
    elif key in {"dbip", "maxmind"}:
        raise NotImplementedError(
            f"GeoIP provider {key!r} is not wired yet; only 'rir' ships in MVP."
        )
    else:
        raise ValueError(f"Unsupported GeoIP provider: {key!r}")

    _cached = provider
    _cached_key = key
    return provider


def reset_cache() -> None:
    """Forget the singleton — tests swap providers via the env var."""
    global _cached, _cached_key
    _cached = None
    _cached_key = None
