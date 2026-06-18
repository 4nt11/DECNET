# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI surface for ``decnet fleet`` (DECNET 1.2 prefork). The fork/restart
mechanism itself is covered by tests/test_prefork.py."""
from __future__ import annotations

from typer.testing import CliRunner

from decnet.cli import app
from decnet.cli.fleet import _FLEETS, _build_fleet

runner = CliRunner()


def test_fleet_is_registered():
    result = runner.invoke(app, ["fleet", "--help"])
    assert result.exit_code == 0
    assert "fleet" in result.stdout.lower()


def test_unknown_fleet_exits_2():
    result = runner.invoke(app, ["fleet", "not-a-fleet"])
    assert result.exit_code == 2
    assert "unknown fleet" in result.stdout


def test_heavy_fleet_builds_expected_workers():
    # _build_fleet imports worker modules + builds thunks but runs nothing
    # (no fork, no repo.initialize) — safe to call in-process.
    specs = _build_fleet("heavy")
    assert set(specs) == {"profiler", "ttp"}
    assert all(callable(t) for t in specs.values())


def test_heavy_is_known():
    assert "heavy" in _FLEETS
