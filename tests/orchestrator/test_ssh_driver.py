"""Driver tests with the docker subprocess mocked.

We don't need a real Docker daemon to validate the driver's contract:
it boils down to "build an argv, call _run, classify the result". A
dependency-injected ``_run`` keeps the tests hermetic.
"""
from __future__ import annotations

import pytest

from decnet.orchestrator.drivers import ssh as ssh_driver
from decnet.orchestrator.drivers.base import ActivityResult
from decnet.orchestrator.scheduler import FileAction, TrafficAction


@pytest.mark.asyncio
async def test_traffic_success_classifies_on_ssh_banner(monkeypatch):
    captured_argv: list[list[str]] = []

    async def fake_run(argv):
        captured_argv.append(argv)
        return 0, "SSH-2.0-OpenSSH_9.6\r\n", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)
    drv = ssh_driver.SSHDriver()
    action = TrafficAction(
        src_uuid="u1", src_name="decky-01",
        dst_uuid="u2", dst_name="decky-02",
        dst_ip="10.0.0.2",
    )
    result = await drv.run(action)
    assert isinstance(result, ActivityResult)
    assert result.success is True
    assert result.payload["banner"].startswith("SSH-2.0-OpenSSH")
    assert captured_argv[0][:3] == ["docker", "exec", "decky-01-ssh"]
    assert captured_argv[0][-1] == "10.0.0.2"


@pytest.mark.asyncio
async def test_traffic_failure_when_banner_missing(monkeypatch):
    async def fake_run(argv):
        return 1, "", "Connection refused"

    monkeypatch.setattr(ssh_driver, "_run", fake_run)
    drv = ssh_driver.SSHDriver()
    action = TrafficAction(
        src_uuid="u1", src_name="decky-01",
        dst_uuid="u2", dst_name="decky-02",
        dst_ip="10.0.0.2",
    )
    result = await drv.run(action)
    assert result.success is False
    assert result.payload["rc"] == 1
    assert "Connection refused" in result.payload["stderr"]


@pytest.mark.asyncio
async def test_file_action_invokes_docker_exec_on_dst(monkeypatch):
    captured: list[tuple[list[str], bytes | None]] = []

    class _FakeProc:
        returncode = 0
        async def communicate(self, input=None):
            return b"", b""
        def kill(self):  # pragma: no cover
            pass

    async def fake_create(*argv, **kw):
        captured.append((list(argv), None))
        proc = _FakeProc()
        orig = proc.communicate

        async def communicate(input=None):
            captured[-1] = (captured[-1][0], input)
            return await orig(None)
        proc.communicate = communicate
        return proc

    # plant_file streams base64 content via stdin to avoid ARG_MAX
    # (mirrors decnet.canary.planter; see commit c17b9e0).  The driver
    # now delegates to decky_io.write_file_to_container, which calls
    # asyncio.create_subprocess_exec — patch that.
    import asyncio as _asyncio
    monkeypatch.setattr(_asyncio, "create_subprocess_exec", fake_create)
    drv = ssh_driver.SSHDriver()
    action = FileAction(
        dst_uuid="u2", dst_name="decky-02",
        path="/tmp/.cache-1700000000.tmp",
        content="session=1700000000\n",
    )
    result = await drv.run(action)
    assert result.success is True
    assert result.payload["bytes"] == len(b"session=1700000000\n")
    argv, stdin_bytes = captured[0]
    assert argv[:4] == ["docker", "exec", "-i", "decky-02-ssh"]
    assert argv[4] == "sh"
    assert argv[5] == "-c"
    sh_cmd = argv[6]
    assert "/tmp/.cache-1700000000.tmp" in sh_cmd
    assert "base64 -d" in sh_cmd
    assert "mkdir -p /tmp" in sh_cmd
    # Content travels base64-encoded on stdin, not interpolated into
    # argv — that's the ARG_MAX-safe + shell-injection-safe contract.
    import base64
    assert stdin_bytes is not None
    assert base64.b64decode(stdin_bytes) == b"session=1700000000\n"


@pytest.mark.asyncio
async def test_run_handles_missing_docker_binary(monkeypatch):
    async def fake_create(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(
        "asyncio.create_subprocess_exec", fake_create,
    )
    rc, out, err = await ssh_driver._run(["docker", "exec", "x", "true"])
    assert rc == 127
    assert "not found" in err


@pytest.mark.asyncio
async def test_plant_file_applies_mtime_via_touch_d(monkeypatch):
    from datetime import datetime, timezone
    captured: list[list[str]] = []

    class _FakeProc:
        returncode = 0
        async def communicate(self, input=None):
            return b"", b""
        def kill(self):  # pragma: no cover
            pass

    async def fake_create(*argv, **kw):
        captured.append(list(argv))
        return _FakeProc()

    import asyncio as _asyncio
    monkeypatch.setattr(_asyncio, "create_subprocess_exec", fake_create)
    drv = ssh_driver.SSHDriver()
    mtime = datetime(2026, 4, 20, 11, 30, 0, tzinfo=timezone.utc)
    result = await drv.plant_file(
        "decky-03", "/home/admin/TODO.md", b"- [ ] rotate keys\n",
        mode=0o644, mtime=mtime,
    )
    assert result.success is True
    sh_cmd = captured[0][6]
    # Backdated mtime appears in the touch -d argument.
    assert "touch -d '2026-04-20 11:30:00 UTC'" in sh_cmd
    assert "chmod 644" in sh_cmd


@pytest.mark.asyncio
async def test_read_file_returns_bytes(monkeypatch):
    async def fake_run(argv):
        assert argv[:3] == ["docker", "exec", "decky-04-ssh"]
        assert argv[3] == "cat"
        return 0, "previous body\n", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)
    drv = ssh_driver.SSHDriver()
    body = await drv.read_file("decky-04", "/home/admin/notes.txt")
    assert body == b"previous body\n"


@pytest.mark.asyncio
async def test_read_file_raises_file_not_found(monkeypatch):
    async def fake_run(argv):
        return 1, "", "cat: /nope: No such file or directory"

    monkeypatch.setattr(ssh_driver, "_run", fake_run)
    drv = ssh_driver.SSHDriver()
    with pytest.raises(FileNotFoundError):
        await drv.read_file("decky-04", "/nope")


@pytest.mark.asyncio
async def test_get_driver_for_dispatches_by_action_type():
    from decnet.orchestrator.drivers import get_driver_for, SSHDriver
    traffic = TrafficAction(
        src_uuid="u1", src_name="a", dst_uuid="u2", dst_name="b",
        dst_ip="10.0.0.1",
    )
    file_a = FileAction(
        dst_uuid="u2", dst_name="b", path="/tmp/x", content="y",
    )
    assert isinstance(get_driver_for(traffic), SSHDriver)
    assert isinstance(get_driver_for(file_a), SSHDriver)


def test_get_driver_for_unknown_action_raises():
    from decnet.orchestrator.drivers import get_driver_for
    class _Bogus:
        pass
    with pytest.raises(TypeError, match="no driver registered"):
        get_driver_for(_Bogus())  # type: ignore[arg-type]
