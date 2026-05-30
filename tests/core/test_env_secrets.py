# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail-closed validation of security-sensitive env secrets (env._require_env).

DECNET_ADMIN_PASSWORD must never silently default to "admin": it is resolved
lazily and validated like DECNET_JWT_SECRET. These tests drive _require_env
against a controlled environ so the production raise paths (which are bypassed
under live pytest) are actually exercised.
"""
from __future__ import annotations

import pytest

import decnet.env as envmod


def _require(monkeypatch: pytest.MonkeyPatch, environ: dict[str, str]) -> str:
    # Replace the whole environ for the call so the PYTEST_* short-circuit in
    # _require_env doesn't fire — we want the real production behaviour.
    monkeypatch.setattr(envmod.os, "environ", dict(environ))
    return envmod._require_env("DECNET_ADMIN_PASSWORD")


def test_admin_password_unset_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="not set"):
        _require(monkeypatch, {})


def test_admin_password_known_bad_default_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="insecure default"):
        _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "admin"})


@pytest.mark.parametrize("bad", ["secret", "password", "changeme", "ADMIN"])
def test_admin_password_other_known_bad_raises(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    with pytest.raises(ValueError, match="insecure default"):
        _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": bad})


def test_admin_password_too_short_raises_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="too short"):
        _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "short1"})


def test_admin_password_short_allowed_in_developer_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    val = _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "short1", "DECNET_DEVELOPER": "true"})
    assert val == "short1"


def test_admin_password_strong_value_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    val = _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "a-strong-unique-password"})
    assert val == "a-strong-unique-password"


def test_pytest_short_circuit_returns_value_unchecked() -> None:
    # Under live pytest (PYTEST_* present), _require_env returns the configured
    # value without the production checks — documents why the dev loop is safe.
    # conftest sets a strong value, so this also proves lazy resolution works.
    assert envmod._require_env("DECNET_ADMIN_PASSWORD") == "test-password-123"


def test_lazy_getattr_resolves_admin_password() -> None:
    # Accessing the attribute (not a module global anymore) routes through
    # __getattr__ -> _require_env.
    assert envmod.DECNET_ADMIN_PASSWORD == "test-password-123"
    with pytest.raises(AttributeError):
        envmod.NOT_A_REAL_SECRET  # noqa: B018
