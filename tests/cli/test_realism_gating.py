# SPDX-License-Identifier: AGPL-3.0-or-later
"""``decnet realism`` is master-only.

Two layers per CLAUDE.md:

* registration-time hide via :data:`MASTER_ONLY_GROUPS` so agents don't
  see ``decnet realism`` in ``--help`` at all,
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


REPO = pathlib.Path(__file__).resolve().parent.parent.parent
DECNET_BIN = Path(sys.executable).parent / "decnet"


def _clean_env(**overrides: str) -> dict[str, str]:
    base = {"PATH": os.environ["PATH"], "HOME": "/nonexistent-for-test"}
    base["DECNET_CONFIG"] = "/nonexistent/decnet.ini"
    base.setdefault("DECNET_JWT_SECRET", "x" * 32)
    base.update(overrides)
    return base


def test_realism_visible_in_master_mode():
    result = subprocess.run(
        [str(DECNET_BIN), "--help"],
        env=_clean_env(DECNET_MODE="master"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0
    assert "realism" in result.stdout


def test_realism_hidden_in_agent_mode():
    result = subprocess.run(
        [str(DECNET_BIN), "--help"],
        env=_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0
    # The sub-app's help string must be gone too — bare "realism" can
    # appear in other command descriptions.
    assert "realism content engine" not in result.stdout


def test_realism_subprocess_import_personas_rejects_in_agent_mode(tmp_path):
    src = tmp_path / "personas.json"
    src.write_text(json.dumps([{
        "name": "X", "email": "x@y.com", "role": "X", "tone": "formal",
        "mannerisms": [],
    }, {
        "name": "Y", "email": "y@y.com", "role": "Y", "tone": "formal",
        "mannerisms": [],
    }]))
    result = subprocess.run(
        [str(DECNET_BIN), "realism", "import-personas", str(src)],
        env=_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"),
        cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0


def test_require_master_mode_body_guard_fires_directly(monkeypatch):
    """Defence-in-depth: even bypassing Typer registration, the body-level
    ``_require_master_mode('realism ...')`` raises ``typer.Exit``.  Same
    mechanism is verified for `api`/`deploy` in test_mode_gating.py."""
    import typer

    from decnet.cli.gating import _require_master_mode

    monkeypatch.setenv("DECNET_MODE", "agent")
    monkeypatch.setenv("DECNET_DISALLOW_MASTER", "true")

    with pytest.raises(typer.Exit):
        _require_master_mode("realism import-personas")


def test_master_mode_falls_through_body_guard(monkeypatch):
    """In master mode the guard is a no-op (raises nothing)."""
    from decnet.cli.gating import _require_master_mode  # noqa: F401

    monkeypatch.setenv("DECNET_MODE", "master")
    # Should simply return.
    _require_master_mode("realism import-personas")
