"""Filesystem layout for GeoIP data.

``GEOIP_ROOT`` is where providers drop their raw files and cache indexes.
Default ``/var/lib/decnet/geoip`` — ``decnet init`` seeds the directory
with ``decnet:decnet`` ownership, mode 0755. Override with
``DECNET_GEOIP_ROOT`` for test harnesses.
"""
from __future__ import annotations

import os
from pathlib import Path

GEOIP_ROOT = Path(os.environ.get("DECNET_GEOIP_ROOT", "/var/lib/decnet/geoip"))


def ensure_root() -> Path:
    """Create ``GEOIP_ROOT`` if absent and return it. No-op if present."""
    GEOIP_ROOT.mkdir(parents=True, exist_ok=True)
    return GEOIP_ROOT
