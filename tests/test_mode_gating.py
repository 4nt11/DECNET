"""CLI mode gating — master-only commands hidden when DECNET_MODE=agent."""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest


REPO = pathlib.Path(__file__).resolve().parent.parent
DECNET_BIN = REPO / ".venv" / "bin" / "decnet"


def _clean_env(**overrides: str) -> dict[str, str]:
    """Env with no DECNET_* / PYTEST_* leakage from the parent test run.

    Keeps only PATH so subprocess can locate the interpreter. HOME is
    stubbed below so .env.local from the user's home doesn't leak in."""
    base = {"PATH": os.environ["PATH"], "HOME": "/nonexistent-for-test"}
    base.update(overrides)
    # Ensure no stale DECNET_CONFIG pointing at some fixture INI
    base["DECNET_CONFIG"] = "/nonexistent/decnet.ini"
    # decnet.web.auth needs a JWT secret to import; provide one so
    # `decnet --help` can walk the command tree.
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


def test_master_mode_lists_master_commands():
    out = _help_text(_clean_env(DECNET_MODE="master"))
    for cmd in ("api", "swarmctl", "swarm", "deploy", "teardown"):
        assert cmd in out, f"expected '{cmd}' in master-mode --help"
    # Agent commands are also visible on master (dual-use hosts).
    for cmd in ("agent", "forwarder", "updater"):
        assert cmd in out


def test_agent_mode_hides_master_commands():
    out = _help_text(_clean_env(DECNET_MODE="agent", DECNET_DISALLOW_MASTER="true"))
    for cmd in ("api", "swarmctl", "deploy", "teardown", "listener"):
        assert cmd not in out, f"'{cmd}' leaked into agent-mode --help"
    # The `swarm` subcommand group must also disappear — identify it by its
    # unique help string (plain 'swarm' appears in other command descriptions).
    assert "Manage swarm workers" not in out
    # Worker-legitimate commands must remain.
    for cmd in ("agent", "forwarder", "updater"):
        assert cmd in out


def test_agent_mode_can_opt_in_to_master_via_disallow_false():
    """A hybrid dev host sets DECNET_DISALLOW_MASTER=false and keeps
    full access even though DECNET_MODE=agent. This is the escape hatch
    for single-machine development."""
    out = _help_text(_clean_env(
        DECNET_MODE="agent", DECNET_DISALLOW_MASTER="false",
    ))
    assert "api" in out
    assert "swarmctl" in out


def test_defence_in_depth_direct_call_fails_in_agent_mode(monkeypatch):
    """Typer's dispatch table hides the command in agent mode, but if
    something imports the command function directly it must still bail.
    _require_master_mode('api') is the belt-and-braces guard."""
    monkeypatch.setenv("DECNET_MODE", "agent")
    monkeypatch.setenv("DECNET_DISALLOW_MASTER", "true")
    # Re-import cli so the module-level gate re-runs (harmless here;
    # we're exercising the in-function guard).
    for mod in list(sys.modules):
        if mod == "decnet.cli":
            sys.modules.pop(mod)
    from decnet.cli import _require_master_mode
    import typer
    with pytest.raises(typer.Exit):
        _require_master_mode("api")
