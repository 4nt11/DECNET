# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sandbox the RPKI validator into a tmp dir so no real
/var/lib/decnet paths get touched and no real RIPE STAT calls are made."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _rpki_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DECNET_RPKI_ENABLED", "true")
    monkeypatch.setenv("DECNET_RPKI_ROOT", str(tmp_path))
    import decnet.rpki.factory as _f
    import decnet.rpki.paths as _p
    monkeypatch.setattr(_p, "RPKI_ROOT", tmp_path)
    _f.reset_cache()
    return tmp_path
