# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASN provider factory — mirror of :mod:`decnet.geoip.factory`.

Dispatch key: ``DECNET_ASN_PROVIDER`` (default ``iptoasn``). Lazy
singleton.
"""
from __future__ import annotations

import os
from typing import Optional

from decnet.asn.base import Provider

_cached: Optional[Provider] = None
_cached_key: Optional[str] = None


def get_provider() -> Provider:
    """Return the configured :class:`Provider` singleton."""
    global _cached, _cached_key
    key = os.environ.get("DECNET_ASN_PROVIDER", "iptoasn").lower()
    if _cached is not None and _cached_key == key:
        return _cached

    if key == "iptoasn":
        from decnet.asn.iptoasn.provider import IptoasnProvider
        provider: Provider = IptoasnProvider()
    else:
        raise ValueError(f"Unsupported ASN provider: {key!r}")

    _cached = provider
    _cached_key = key
    return provider


def reset_cache() -> None:
    """Forget the singleton — tests swap providers via the env var."""
    global _cached, _cached_key
    _cached = None
    _cached_key = None
