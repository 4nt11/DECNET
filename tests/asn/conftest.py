# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-package fixtures — sandbox the ASN provider into a tmp dir so no
real /var/lib/decnet paths get touched and no real iptoasn URL gets
fetched."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _asn_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DECNET_ASN_ENABLED", "true")
    monkeypatch.setenv("DECNET_ASN_ROOT", str(tmp_path))
    import decnet.asn as _a
    import decnet.asn.factory as _f
    import decnet.asn.paths as _p
    monkeypatch.setattr(_p, "ASN_ROOT", tmp_path)
    _a._lookup = None
    _a._provider_name = None
    _f.reset_cache()
    return tmp_path
