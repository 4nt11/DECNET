"""``decnet emailgen`` is master-only.

Two layers per CLAUDE.md:

* registration-time hide via :data:`MASTER_ONLY_GROUPS` so agents don't
  see ``decnet emailgen`` in ``--help`` at all,
* body-guard ``_require_master_mode()`` so a direct callable import (e.g.
  from a third-party tool) still bails on agent hosts.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner


REPO = pathlib.Path(__file__).resolve().parent.parent.parent
DECNET_BIN = Path(sys.executable).parent / "decnet"


def _clean_env(**overrides: str) -> dict[str, str]:
    base = {"PATH": os.environ["PATH"], "HOME": "/nonexistent-for-test"}
    base["DECNET_CONFIG"] = "/nonexistent/decnet.ini"
    base.setdefault("DECNET_JWT_SECRET", "x" * 32)
    base.update(overrides)
    return base


def test_emailgen_visible_in_master_mode():
    result = subprocess.run(
        [str(DECNET_BIN), "--help"],
        env=_clean_env(DECNET_MODE="master"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0
    assert "emailgen" in result.stdout


def test_emailgen_hidden_in_agent_mode():
    result = subprocess.run(
        [str(DECNET_BIN), "--help"],
        env=_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0
    # The sub-app's help string must be gone too — bare "emailgen" can
    # appear in other command descriptions.
    assert "Drip persona-driven fake corporate email" not in result.stdout


def test_emailgen_subprocess_run_rejects_in_agent_mode():
    """Subprocess-level: a fresh Python invocation of `decnet emailgen
    run` under DECNET_MODE=agent must exit non-zero (gate hides the
    sub-app, so the command is unknown to Typer)."""
    result = subprocess.run(
        [str(DECNET_BIN), "emailgen", "run"],
        env=_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0


def test_emailgen_subprocess_import_personas_rejects_in_agent_mode(tmp_path):
    src = tmp_path / "personas.json"
    src.write_text(json.dumps([{
        "name": "X", "email": "x@y.com", "role": "X", "tone": "formal",
        "mannerisms": [],
    }, {
        "name": "Y", "email": "y@y.com", "role": "Y", "tone": "formal",
        "mannerisms": [],
    }]))
    result = subprocess.run(
        [str(DECNET_BIN), "emailgen", "import-personas", str(src)],
        env=_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0


def test_require_master_mode_body_guard_fires_directly(monkeypatch):
    """Defence-in-depth: even bypassing Typer registration, the body-level
    ``_require_master_mode('emailgen ...')`` raises ``typer.Exit``.  Same
    mechanism is verified for `api`/`deploy` in test_mode_gating.py."""
    import typer

    from decnet.cli.gating import _require_master_mode

    monkeypatch.setenv("DECNET_MODE", "agent")
    monkeypatch.setenv("DECNET_DISALLOW_MASTER", "true")

    with pytest.raises(typer.Exit):
        _require_master_mode("emailgen run")


def test_master_mode_falls_through_body_guard(monkeypatch):
    """In master mode the guard is a no-op (raises nothing)."""
    from decnet.cli.gating import _require_master_mode

    monkeypatch.setenv("DECNET_MODE", "master")
    # Should simply return.
    _require_master_mode("emailgen run")
