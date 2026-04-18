"""CLI surface for `decnet forwarder`. Only guard clauses — the async
loop itself is covered by tests/swarm/test_log_forwarder.py."""
from __future__ import annotations

import pathlib

import pytest
from typer.testing import CliRunner

from decnet.cli import app


runner = CliRunner()


def test_forwarder_requires_master_host(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    monkeypatch.delenv("DECNET_SWARM_MASTER_HOST", raising=False)
    # Also patch the already-imported module-level constant.
    monkeypatch.setattr("decnet.env.DECNET_SWARM_MASTER_HOST", None, raising=False)
    result = runner.invoke(app, ["forwarder", "--log-file", str(tmp_path / "decnet.log")])
    assert result.exit_code == 2
    assert "master-host" in result.output


def test_forwarder_requires_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    agent_dir = tmp_path / "agent"  # empty
    log_file = tmp_path / "decnet.log"
    log_file.write_text("")
    result = runner.invoke(
        app,
        [
            "forwarder",
            "--master-host", "127.0.0.1",
            "--log-file", str(log_file),
            "--agent-dir", str(agent_dir),
        ],
    )
    assert result.exit_code == 2
    assert "bundle" in result.output
