# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI surface for ``decnet supervise`` (DECNET 1.1 consolidation)."""
from __future__ import annotations

from typer.testing import CliRunner

from decnet.cli import app
from decnet.cli.supervise import _GROUPS

runner = CliRunner()


def test_supervise_is_registered():
    result = runner.invoke(app, ["supervise", "--help"])
    assert result.exit_code == 0
    assert "group" in result.stdout.lower()


def test_unknown_group_exits_2():
    result = runner.invoke(app, ["supervise", "definitely-not-a-group"])
    assert result.exit_code == 2
    assert "unknown group" in result.stdout


def test_batch_group_is_known():
    assert "batch" in _GROUPS
