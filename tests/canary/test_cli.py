"""Smoke coverage for the ``decnet canary`` CLI subcommand.

We don't run the worker (it would block on HTTP/DNS sockets) — we
just confirm the command is registered and not master-gated, so an
agent host can run ``decnet canary`` without the gate hiding it.
"""
from __future__ import annotations

from typer.testing import CliRunner

from decnet.cli import app
from decnet.cli.gating import MASTER_ONLY_COMMANDS


def test_canary_command_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["canary", "--help"])
    assert result.exit_code == 0
    assert "Run the canary HTTP + DNS callback receiver" in result.output


def test_canary_is_not_master_only() -> None:
    # Agents must be able to run their own canary worker.
    assert "canary" not in MASTER_ONLY_COMMANDS
