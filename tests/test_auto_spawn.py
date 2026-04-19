"""Auto-spawn of forwarder from `decnet agent` (and listener from
`decnet swarmctl`, added in a later patch).

These tests monkeypatch subprocess.Popen inside decnet.cli so no real
process is ever forked. We assert on the Popen call shape — argv,
start_new_session, stdio redirection — plus PID-file correctness.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest


class _FakePopen:
    """Minimal Popen stub. Records the call; reports a fake PID."""
    last_instance: "None | _FakePopen" = None

    def __init__(self, argv: list[str], **kwargs: Any) -> None:
        self.argv = argv
        self.kwargs = kwargs
        self.pid = 424242
        _FakePopen.last_instance = self


@pytest.fixture
def fake_popen(monkeypatch):
    import decnet.cli as cli_mod
    # Patch the subprocess module _spawn_detached reaches via its local
    # import. Easier: patch subprocess.Popen globally in the subprocess
    # module, since _spawn_detached uses `import subprocess` locally.
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    _FakePopen.last_instance = None
    return cli_mod


def test_spawn_detached_sets_new_session_and_writes_pid(fake_popen, tmp_path):
    pid_file = tmp_path / "forwarder.pid"
    pid = fake_popen._spawn_detached(
        ["/usr/bin/true", "--flag"], pid_file,
    )
    # The helper returns the pid from the Popen instance.
    assert pid == 424242
    # PID file exists and contains a valid positive integer.
    raw = pid_file.read_text().strip()
    assert raw.isdigit(), f"PID file not numeric: {raw!r}"
    assert int(raw) > 0, "PID file must contain a positive integer"
    assert int(raw) == pid
    # Detach flags were passed.
    call = _FakePopen.last_instance
    assert call is not None
    assert call.kwargs["start_new_session"] is True
    assert call.kwargs["close_fds"] is True
    # stdin/stdout/stderr were redirected (file handles, not None).
    assert call.kwargs["stdin"] is not None
    assert call.kwargs["stdout"] is not None
    assert call.kwargs["stderr"] is not None


def test_pid_file_parent_is_created(fake_popen, tmp_path):
    nested = tmp_path / "run" / "decnet" / "forwarder.pid"
    assert not nested.parent.exists()
    fake_popen._spawn_detached(["/usr/bin/true"], nested)
    assert nested.exists()
    assert int(nested.read_text().strip()) > 0


def test_agent_autospawns_forwarder(fake_popen, monkeypatch, tmp_path):
    """`decnet agent` calls _spawn_detached once with a forwarder argv."""
    # Isolate PID dir to tmp_path so the test doesn't touch /opt/decnet.
    monkeypatch.setattr(fake_popen, "_pid_dir", lambda: tmp_path)
    # Set master host so the auto-spawn branch fires.
    monkeypatch.setenv("DECNET_SWARM_MASTER_HOST", "10.0.0.1")
    monkeypatch.setenv("DECNET_SWARM_SYSLOG_PORT", "6514")
    # Stub the actual agent server so the command body returns fast.
    from decnet.agent import server as _agent_server
    monkeypatch.setattr(_agent_server, "run", lambda *a, **k: 0)

    # We also need to re-read DECNET_SWARM_MASTER_HOST through env.py at
    # call time. env.py already read it at import, so patch on the module.
    from decnet import env as _env
    monkeypatch.setattr(_env, "DECNET_SWARM_MASTER_HOST", "10.0.0.1")

    from typer.testing import CliRunner
    runner = CliRunner()
    # Invoke the agent command directly (without --daemon to avoid
    # double-forking the pytest worker).
    result = runner.invoke(fake_popen.app, ["agent", "--port", "8765"])
    # Agent server was stubbed → exit=0; the important thing is the Popen
    # got called with a forwarder argv.
    assert result.exit_code == 0, result.stdout
    call = _FakePopen.last_instance
    assert call is not None, "expected _spawn_detached → Popen to fire"
    assert "forwarder" in call.argv
    assert "--master-host" in call.argv
    assert "10.0.0.1" in call.argv
    assert "--daemon" in call.argv
    # PID file was written in the test tmpdir, not /opt/decnet.
    assert (tmp_path / "forwarder.pid").exists()


def test_agent_no_forwarder_flag_suppresses_spawn(fake_popen, monkeypatch, tmp_path):
    monkeypatch.setattr(fake_popen, "_pid_dir", lambda: tmp_path)
    monkeypatch.setenv("DECNET_SWARM_MASTER_HOST", "10.0.0.1")
    from decnet.agent import server as _agent_server
    monkeypatch.setattr(_agent_server, "run", lambda *a, **k: 0)
    from decnet import env as _env
    monkeypatch.setattr(_env, "DECNET_SWARM_MASTER_HOST", "10.0.0.1")

    from typer.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(fake_popen.app, ["agent", "--no-forwarder"])
    assert result.exit_code == 0, result.stdout
    assert _FakePopen.last_instance is None, "forwarder should NOT have been spawned"
    assert not (tmp_path / "forwarder.pid").exists()


def test_agent_skips_forwarder_when_master_unset(fake_popen, monkeypatch, tmp_path):
    """If DECNET_SWARM_MASTER_HOST is not set, auto-spawn is silently
    skipped — we don't know where to ship logs to."""
    monkeypatch.setattr(fake_popen, "_pid_dir", lambda: tmp_path)
    monkeypatch.delenv("DECNET_SWARM_MASTER_HOST", raising=False)
    from decnet.agent import server as _agent_server
    monkeypatch.setattr(_agent_server, "run", lambda *a, **k: 0)
    from decnet import env as _env
    monkeypatch.setattr(_env, "DECNET_SWARM_MASTER_HOST", None)

    from typer.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(fake_popen.app, ["agent"])
    assert result.exit_code == 0
    assert _FakePopen.last_instance is None
