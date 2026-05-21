"""Filesystem layout for RPKI data — mirror of :mod:`decnet.asn.paths`.

``RPKI_ROOT`` is where the validator stores its SQLite cache.
Default ``/var/lib/decnet/rpki``. Override with ``DECNET_RPKI_ROOT``
for test harnesses.
"""
from __future__ import annotations

import os
from pathlib import Path

RPKI_ROOT = Path(os.environ.get("DECNET_RPKI_ROOT", "/var/lib/decnet/rpki"))


def ensure_root() -> Path:
    """Create ``RPKI_ROOT`` if absent and return it. No-op if present."""
    RPKI_ROOT.mkdir(parents=True, exist_ok=True)
    return RPKI_ROOT
