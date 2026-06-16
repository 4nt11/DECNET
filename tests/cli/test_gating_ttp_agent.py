# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agent-mode gating for the `ttp` worker (DEBT-047).

`decnet ttp` runs the live TTP-tagging worker against local bus events
and the local artifacts tree. After DEBT-047 it MUST be available on
agent hosts so EmailLifter R0047 (BEC) can disk-reach .eml files
without round-tripping raw body text through the master.

`decnet ttp-backfill` walks the master DB and stays master-only.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
from pathlib import Path


REPO = pathlib.Path(__file__).resolve().parent.parent.parent
DECNET_BIN = Path(sys.executable).parent / "decnet"


def _clean_env(**overrides: str) -> dict[str, str]:
    base = {"PATH": os.environ["PATH"], "HOME": "/nonexistent-for-test"}
    base.update(overrides)
    base["DECNET_CONFIG"] = "/nonexistent/decnet.ini"
    base.setdefault("DECNET_JWT_SECRET", "x" * 32)
    return base


def _help_text(env: dict[str, str]) -> str:
    result = subprocess.run(
        [str(DECNET_BIN), "--help"],
        env=env, cwd=str(REPO),
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_ttp_visible_on_agent_mode():
    out = _help_text(_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"))
    assert "ttp " in out or "ttp\n" in out, (
        "`ttp` worker must be agent-runnable after DEBT-047 (disk-reach unblock)"
    )


def test_ttp_backfill_hidden_on_agent_mode():
    out = _help_text(_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"))
    assert "ttp-backfill" not in out, (
        "`ttp-backfill` walks the master DB and must stay master-only"
    )


def test_ttp_visible_on_master_mode():
    out = _help_text(_clean_env(DECNET_MODE="master"))
    assert "ttp " in out or "ttp\n" in out
    assert "ttp-backfill" in out


def test_master_only_set_excludes_ttp():
    """Source-level guard against re-adding `ttp` to the master-only set."""
    from decnet.cli.gating import MASTER_ONLY_COMMANDS
    assert "ttp" not in MASTER_ONLY_COMMANDS
    assert "ttp-backfill" in MASTER_ONLY_COMMANDS
