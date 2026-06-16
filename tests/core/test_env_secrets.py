# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail-closed validation of security-sensitive env secrets (env._require_env).

DECNET_ADMIN_PASSWORD must never silently default to "admin": it is resolved
lazily and validated like DECNET_JWT_SECRET. These tests drive _require_env
against a controlled environ so the production raise paths (which are bypassed
under the test harness via DECNET_TESTING=1) are actually exercised.
"""
from __future__ import annotations

import pytest

import decnet.env as envmod


def _require(monkeypatch: pytest.MonkeyPatch, environ: dict[str, str]) -> str:
    # Replace the whole environ for the call so the DECNET_TESTING short-circuit
    # in _require_env doesn't fire — we want the real production behaviour.
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


def test_known_bad_message_does_not_leak_secret_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # V7.1.3: the known-bad rejection must NOT echo the rejected secret value
    # (it would land in logs / stderr / crash reporters). Name the variable,
    # not its value.
    secret = "admin"
    with pytest.raises(ValueError) as exc:
        _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": secret})
    msg = str(exc.value)
    assert secret not in msg
    assert "DECNET_ADMIN_PASSWORD" in msg


def test_admin_password_too_short_raises_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="too short"):
        _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "short1"})


def test_admin_password_short_allowed_in_developer_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    val = _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "short1", "DECNET_DEVELOPER": "true"})
    assert val == "short1"


def test_admin_password_strong_value_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    val = _require(monkeypatch, {"DECNET_ADMIN_PASSWORD": "a-strong-unique-password"})
    assert val == "a-strong-unique-password"


def test_testing_flag_short_circuit_returns_value_unchecked() -> None:
    # Under the test harness (DECNET_TESTING=1, set in conftest), _require_env
    # returns the configured value without the production checks — documents
    # why the dev loop is safe. conftest sets a strong value, so this also
    # proves lazy resolution works.
    assert envmod._require_env("DECNET_ADMIN_PASSWORD") == "test-password-123"


def test_pytest_var_leak_does_not_bypass_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    # V2.1.7 regression: a leaked PYTEST_* env var must NOT disable strength
    # validation. With DECNET_TESTING unset, a known-bad / short secret is
    # still rejected even though a PYTEST_* var is present.
    monkeypatch.setattr(
        envmod.os,
        "environ",
        {"PYTEST_CURRENT_TEST": "x", "DECNET_ADMIN_PASSWORD": "admin"},
    )
    with pytest.raises(ValueError):
        envmod._require_env("DECNET_ADMIN_PASSWORD")
    monkeypatch.setattr(
        envmod.os,
        "environ",
        {"PYTEST_CURRENT_TEST": "x", "DECNET_ADMIN_PASSWORD": "short1"},
    )
    with pytest.raises(ValueError):
        envmod._require_env("DECNET_ADMIN_PASSWORD")


def test_lazy_getattr_resolves_admin_password() -> None:
    # Accessing the attribute (not a module global anymore) routes through
    # __getattr__ -> _require_env.
    assert envmod.DECNET_ADMIN_PASSWORD == "test-password-123"
    with pytest.raises(AttributeError):
        envmod.NOT_A_REAL_SECRET  # noqa: B018
