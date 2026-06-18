# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prefork supervisor behaviour, exercised via a subprocess driver so no fork
happens inside the pytest/xdist worker (which would be unsafe).

Proves: workers fork and run, a crashing worker is restarted with backoff, and
the fleet shuts down cleanly (stop_after returns, no orphaned children).
"""
from __future__ import annotations

import pathlib
import subprocess
import sys


def test_prefork_runs_and_restarts(tmp_path: pathlib.Path):
    driver = pathlib.Path(__file__).parent / "prefork_driver.py"
    proc = subprocess.run(
        [sys.executable, str(driver), str(tmp_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"driver failed:\n{proc.stderr}"

    tick = (tmp_path / "tick.log").read_text().splitlines()
    crash = (tmp_path / "crash.log").read_text().splitlines()

    # tick ran continuously for ~2s at 0.2s cadence → several lines.
    assert len(tick) >= 5, f"tick worker did not stay up: {len(tick)} lines"
    # crasher died fast and was restarted repeatedly → many markers.
    assert len(crash) >= 3, f"crasher was not restarted: {len(crash)} markers"


def test_empty_fleet_returns(tmp_path: pathlib.Path):
    # run_fleet([]) must be a no-op, not hang.
    code = (
        "from decnet.prefork import run_fleet; run_fleet({}, stop_after=5)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=15
    )
    assert proc.returncode == 0, proc.stderr
