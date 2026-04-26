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
    captured_argv: list[list[str]] = []

    async def fake_run(argv):
        captured_argv.append(argv)
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)
    drv = ssh_driver.SSHDriver()
    action = FileAction(
        dst_uuid="u2", dst_name="decky-02",
        path="/tmp/.cache-1700000000.tmp",
        content="session=1700000000\n",
    )
    result = await drv.run(action)
    assert result.success is True
    assert result.payload["bytes"] == len("session=1700000000\n".encode())
    argv = captured_argv[0]
    assert argv[:3] == ["docker", "exec", "decky-02-ssh"]
    assert argv[3] == "sh"
    assert argv[4] == "-c"
    # The shell payload must single-quote both the content and the path —
    # any unquoted ``;`` or ``$`` here would mean a shell-injection bug.
    sh_cmd = argv[5]
    # Path appears (shlex.quote leaves safe paths unquoted) and content
    # is single-quoted — that's the shell-injection-safe contract.
    assert "/tmp/.cache-1700000000.tmp" in sh_cmd
    assert "'session=1700000000\n'" in sh_cmd
    assert "mkdir -p /tmp" in sh_cmd


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
