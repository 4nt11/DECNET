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
    from decnet.cli import utils as _cli_utils
    monkeypatch.setattr(_cli_utils, "_pid_dir", lambda: tmp_path)
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
    from decnet.cli import utils as _cli_utils
    monkeypatch.setattr(_cli_utils, "_pid_dir", lambda: tmp_path)
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
    from decnet.cli import utils as _cli_utils
    monkeypatch.setattr(_cli_utils, "_pid_dir", lambda: tmp_path)
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


# ───────────────────────────────────────────────────────────────────────────
# swarmctl → listener auto-spawn
# ───────────────────────────────────────────────────────────────────────────

class _FakeUvicornPopen:
    """Stub for the uvicorn subprocess inside swarmctl — returns immediately
    so the Typer command body doesn't block on proc.wait()."""
    def __init__(self, *a, **kw) -> None:
        self.pid = 999999
    def wait(self, *a, **kw) -> int:
        return 0


@pytest.fixture
def fake_swarmctl_popen(monkeypatch):
    """For swarmctl: record the detached listener spawn via _FakePopen
    AND stub uvicorn's Popen so swarmctl's body returns immediately."""
    import decnet.cli as cli_mod
    import subprocess as _subp

    calls: list[_FakePopen] = []

    def _router(argv, **kwargs):
        # Only the listener auto-spawn uses start_new_session + DEVNULL stdio.
        if kwargs.get("start_new_session") and "stdin" in kwargs:
            inst = _FakePopen(argv, **kwargs)
            calls.append(inst)
            return inst
        # Anything else (the uvicorn child swarmctl blocks on) → cheap stub.
        return _FakeUvicornPopen()

    monkeypatch.setattr(_subp, "Popen", _router)
    _FakePopen.last_instance = None
    return cli_mod, calls


def test_swarmctl_autospawns_listener(fake_swarmctl_popen, monkeypatch, tmp_path):
    cli_mod, calls = fake_swarmctl_popen
    from decnet.cli import utils as _cli_utils
    monkeypatch.setattr(_cli_utils, "_pid_dir", lambda: tmp_path)
    monkeypatch.setenv("DECNET_LISTENER_HOST", "0.0.0.0")
    monkeypatch.setenv("DECNET_SWARM_SYSLOG_PORT", "6514")

    from typer.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(cli_mod.app, ["swarmctl", "--port", "8770"])
    assert result.exit_code == 0, result.stdout
    assert len(calls) == 1, f"expected one detached spawn, got {len(calls)}"
    argv = calls[0].argv
    assert "listener" in argv
    assert "--daemon" in argv
    assert "--port" in argv and "6514" in argv
    # PID file written.
    pid_path = tmp_path / "listener.pid"
    assert pid_path.exists()
    assert int(pid_path.read_text().strip()) > 0


def test_swarmctl_no_listener_flag_suppresses_spawn(fake_swarmctl_popen, monkeypatch, tmp_path):
    cli_mod, calls = fake_swarmctl_popen
    from decnet.cli import utils as _cli_utils
    monkeypatch.setattr(_cli_utils, "_pid_dir", lambda: tmp_path)

    from typer.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(cli_mod.app, ["swarmctl", "--no-listener"])
    assert result.exit_code == 0, result.stdout
    assert calls == [], "listener should NOT have been spawned"
    assert not (tmp_path / "listener.pid").exists()
