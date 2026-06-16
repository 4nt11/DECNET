# SPDX-License-Identifier: AGPL-3.0-or-later
"""Filesystem layout for ASN data — mirror of :mod:`decnet.geoip.paths`.

``ASN_ROOT`` is where providers drop their raw files and cache indexes.
Default ``/var/lib/decnet/asn``. Override with ``DECNET_ASN_ROOT`` for
test harnesses.
"""
from __future__ import annotations

import os
from pathlib import Path

ASN_ROOT = Path(os.environ.get("DECNET_ASN_ROOT", "/var/lib/decnet/asn"))


def ensure_root() -> Path:
    """Create ``ASN_ROOT`` if absent and return it. No-op if present."""
    ASN_ROOT.mkdir(parents=True, exist_ok=True)
    return ASN_ROOT
