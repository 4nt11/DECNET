"""RPKI validator factory — mirror of :mod:`decnet.asn.factory`.

Dispatch key: ``DECNET_RPKI_PROVIDER`` (default ``ripestat``). Lazy
singleton.
"""
from __future__ import annotations

import os
from typing import Optional

from decnet.rpki.base import Validator

_cached: Optional[Validator] = None
_cached_key: Optional[str] = None


def get_validator() -> Validator:
    """Return the configured :class:`Validator` singleton."""
    global _cached, _cached_key
    key = os.environ.get("DECNET_RPKI_PROVIDER", "ripestat").lower()
    if _cached is not None and _cached_key == key:
        return _cached

    if key == "ripestat":
        from decnet.rpki.ripestat.validator import RipeStatValidator
        validator: Validator = RipeStatValidator()
    else:
        raise ValueError(f"Unsupported RPKI provider: {key!r}")

    _cached = validator
    _cached_key = key
    return validator


def reset_cache() -> None:
    """Forget the singleton — tests swap validators via the env var."""
    global _cached, _cached_key
    _cached = None
    _cached_key = None
