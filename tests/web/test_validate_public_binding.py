# SPDX-License-Identifier: AGPL-3.0-or-later
"""validate_public_binding refuses footgun configs at master startup.

The validator no-ops under pytest by design (so unit tests in unrelated
modules don't have to set five env vars per fixture); these tests strip
the PYTEST_* vars before calling it so the real code path runs.
"""
from __future__ import annotations

import importlib
import sys

import pytest


def _reimport_env(monkeypatch: pytest.MonkeyPatch):
    for mod in list(sys.modules):
        if mod == "decnet.env" or mod.startswith("decnet.env."):
            sys.modules.pop(mod)
    return importlib.import_module("decnet.env")


def _strip_pytest_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    import os
    for k in list(os.environ):
        if k.startswith("PYTEST"):
            monkeypatch.delenv(k, raising=False)


def test_validator_noop_on_loopback_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_API_HOST", "127.0.0.1")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "http://localhost:8080")
    env = _reimport_env(monkeypatch)
    _strip_pytest_vars(monkeypatch)
    env.validate_public_binding()  # no raise


def test_validator_rejects_loopback_cors_on_public_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DECNET_API_HOST", "0.0.0.0")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "http://localhost:8080")
    env = _reimport_env(monkeypatch)
    _strip_pytest_vars(monkeypatch)
    with pytest.raises(ValueError, match="loopback origin"):
        env.validate_public_binding()


def test_validator_accepts_public_cors_on_public_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DECNET_API_HOST", "0.0.0.0")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "https://dashboard.example.com")
    env = _reimport_env(monkeypatch)
    _strip_pytest_vars(monkeypatch)
    env.validate_public_binding()  # no raise


def test_validator_rejects_plaintext_canary_on_public_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DECNET_API_HOST", "0.0.0.0")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "https://dashboard.example.com")
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "http://canary.example.com:8088")
    env = _reimport_env(monkeypatch)
    _strip_pytest_vars(monkeypatch)
    with pytest.raises(ValueError, match="plaintext HTTP"):
        env.validate_public_binding()


def test_validator_allows_loopback_canary_even_on_public_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Local canary endpoint behind the master is fine; only public-facing
    # plaintext is the footgun.
    monkeypatch.setenv("DECNET_API_HOST", "0.0.0.0")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "https://dashboard.example.com")
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "http://localhost:8088")
    env = _reimport_env(monkeypatch)
    _strip_pytest_vars(monkeypatch)
    env.validate_public_binding()  # no raise


def test_validator_skips_under_pytest(monkeypatch: pytest.MonkeyPatch) -> None:
    # With PYTEST_* still in env (default), even a misconfigured env passes —
    # this is the deliberate bypass so unrelated tests don't trip on it.
    monkeypatch.setenv("DECNET_API_HOST", "0.0.0.0")
    monkeypatch.setenv("DECNET_CORS_ORIGINS", "http://localhost:8080")
    env = _reimport_env(monkeypatch)
    env.validate_public_binding()  # no raise — guard short-circuits
