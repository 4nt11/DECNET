# SPDX-License-Identifier: AGPL-3.0-or-later
"""The JWT secret must be lazy: agent/updater subcommands should import
`decnet.env` without DECNET_JWT_SECRET being set."""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


def _reimport_env(monkeypatch):
    monkeypatch.delenv("DECNET_JWT_SECRET", raising=False)
    for mod in list(sys.modules):
        if mod == "decnet.env" or mod.startswith("decnet.env."):
            sys.modules.pop(mod)
    return importlib.import_module("decnet.env")


def test_env_imports_without_jwt_secret(monkeypatch):
    env = _reimport_env(monkeypatch)
    assert hasattr(env, "DECNET_API_PORT")


def test_jwt_secret_access_returns_value_when_set(monkeypatch):
    monkeypatch.setenv("DECNET_JWT_SECRET", "x" * 32)
    env = _reimport_env(monkeypatch)
    monkeypatch.setenv("DECNET_JWT_SECRET", "x" * 32)
    assert env.DECNET_JWT_SECRET == "x" * 32


def test_agent_cli_imports_without_jwt_secret(monkeypatch, tmp_path):
    """Subprocess check: `decnet agent --help` must succeed with no
    DECNET_JWT_SECRET in the environment and no .env file in cwd."""
    import subprocess
    import pathlib
    clean_env = {
        k: v for k, v in os.environ.items()
        if not k.startswith("DECNET_") and not k.startswith("PYTEST")
    }
    clean_env["PATH"] = os.environ["PATH"]
    clean_env["HOME"] = str(tmp_path)
    repo = pathlib.Path(__file__).resolve().parent.parent.parent
    # binary = repo / ".venv" / "bin" / "decnet"
    binary = Path(sys.executable).parent / "decnet"
    result = subprocess.run(
        [str(binary), "agent", "--help"],
        cwd=str(tmp_path),
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "worker agent" in result.stdout.lower()


def test_unknown_attr_still_raises(monkeypatch):
    env = _reimport_env(monkeypatch)
    with pytest.raises(AttributeError):
        _ = env.DOES_NOT_EXIST
