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


def test_install_toolchain_command_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["canary-install-toolchain", "--help"])
    assert result.exit_code == 0
    assert "fingerprint" in result.output.lower()


def test_install_toolchain_fails_when_npm_missing(tmp_path, monkeypatch) -> None:
    """Without npm on PATH the command exits non-zero with a clear message."""
    runner = CliRunner()
    # Force shutil.which to return None for our chosen sentinel name.
    result = runner.invoke(
        app, ["canary-install-toolchain", "--npm-bin", "/nonexistent/npm-xyz"],
    )
    assert result.exit_code != 0
    assert "not found" in result.output.lower()


def test_install_toolchain_invokes_npm_in_canary_dir(monkeypatch) -> None:
    """Successful path: subprocess.run called with the right argv + cwd."""
    import subprocess as _sp
    import shutil as _shutil
    from pathlib import Path

    import decnet.canary as _canary_pkg

    monkeypatch.setattr(_shutil, "which", lambda _x: "/usr/bin/npm-stub")

    captured: dict = {}

    def _fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        captured["argv"] = argv
        captured["cwd"] = kwargs.get("cwd")
        return _sp.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("decnet.cli.canary.subprocess.run", _fake_run)

    runner = CliRunner()
    result = runner.invoke(app, ["canary-install-toolchain"])
    assert result.exit_code == 0, result.output
    assert captured["argv"][0] == "npm"
    assert captured["argv"][1:4] == ["install", "--omit=dev", "--no-fund"]
    expected_dir = str(Path(_canary_pkg.__file__).resolve().parent)
    assert captured["cwd"] == expected_dir
