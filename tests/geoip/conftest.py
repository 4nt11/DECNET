# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-package fixtures — flip DECNET_GEOIP_ENABLED back on for geoip tests
and point the provider at a tmp dir so no real /var/lib/decnet paths get
touched and no real RIR URL gets fetched.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _geoip_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DECNET_GEOIP_ENABLED", "true")
    monkeypatch.setenv("DECNET_GEOIP_ROOT", str(tmp_path))
    # Reset module-level caches so the env swap takes effect.
    import decnet.geoip as _g
    import decnet.geoip.factory as _f
    import decnet.geoip.paths as _p
    monkeypatch.setattr(_p, "GEOIP_ROOT", tmp_path)
    _g._lookup = None
    _g._provider_name = None
    _f.reset_cache()
    return tmp_path
