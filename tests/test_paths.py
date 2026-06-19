# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the shared runtime-path probe."""
from __future__ import annotations

from decnet.paths import resolve_runtime_path


def _resolve(tmp_path, env=None, runtime_dir=None):
    return resolve_runtime_path(
        "x.sock",
        env_var="DECNET_TEST_PATH",
        runtime_dir=str(runtime_dir if runtime_dir is not None else tmp_path),
        user_fallback="~/.decnet/x.sock",
    )


def test_env_override_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("DECNET_TEST_PATH", "/explicit/here.sock")
    assert _resolve(tmp_path) == "/explicit/here.sock"


def test_writable_runtime_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("DECNET_TEST_PATH", raising=False)
    assert _resolve(tmp_path) == str(tmp_path / "x.sock")


def test_falls_back_when_runtime_dir_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("DECNET_TEST_PATH", raising=False)
    missing = tmp_path / "nope"  # does not exist → not a writable dir
    result = _resolve(tmp_path, runtime_dir=missing)
    assert result.endswith("/.decnet/x.sock")
    assert "~" not in result  # tilde expanded
