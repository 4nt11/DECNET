# SPDX-License-Identifier: AGPL-3.0-or-later
"""Access-token lifetime is configurable via DECNET_JWT_EXP_MINUTES, defaults
to 4h, and rejects non-positive / non-integer values at import time."""
from __future__ import annotations

import importlib
import sys

import pytest


def _reimport_env(monkeypatch, value: str | None):
    if value is None:
        monkeypatch.delenv("DECNET_JWT_EXP_MINUTES", raising=False)
    else:
        monkeypatch.setenv("DECNET_JWT_EXP_MINUTES", value)
    for mod in list(sys.modules):
        if mod == "decnet.env" or mod.startswith("decnet.env."):
            sys.modules.pop(mod)
    return importlib.import_module("decnet.env")


def test_default_is_four_hours(monkeypatch):
    env = _reimport_env(monkeypatch, None)
    assert env.DECNET_JWT_EXP_MINUTES == 240


def test_override_is_honored(monkeypatch):
    env = _reimport_env(monkeypatch, "30")
    assert env.DECNET_JWT_EXP_MINUTES == 30


def test_non_integer_rejected(monkeypatch):
    with pytest.raises(ValueError, match="must be an integer"):
        _reimport_env(monkeypatch, "soon")


@pytest.mark.parametrize("bad", ["0", "-5"])
def test_non_positive_rejected(monkeypatch, bad):
    with pytest.raises(ValueError, match="positive integer"):
        _reimport_env(monkeypatch, bad)


def test_auth_module_tracks_env(monkeypatch):
    """decnet.web.auth.ACCESS_TOKEN_EXPIRE_MINUTES reflects the env var."""
    def _drop():
        for mod in ("decnet.env", "decnet.web.auth"):
            sys.modules.pop(mod, None)

    monkeypatch.setenv("DECNET_JWT_EXP_MINUTES", "45")
    monkeypatch.setenv("DECNET_JWT_SECRET", "x" * 32)
    _drop()
    try:
        auth = importlib.import_module("decnet.web.auth")
        assert auth.ACCESS_TOKEN_EXPIRE_MINUTES == 45
    finally:
        # Don't leak a 45-minute auth module into the rest of the suite — force
        # a clean rebuild from the (monkeypatch-restored) environment.
        _drop()
