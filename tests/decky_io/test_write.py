"""Unit coverage for decnet.decky_io.write — the docker-exec wrapper.

Mirrors the canary planter's subprocess-mock pattern: we patch
:func:`asyncio.create_subprocess_exec` so the tests don't require a
docker daemon, then assert argv shape, stdin payload, and the
``mtime`` / ``mode`` knobs land in the rendered ``sh -c`` script.
"""
from __future__ import annotations

import asyncio
import base64
import re
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from decnet.decky_io import (
    delete_file_from_container,
    write_file_to_container,
)


class _FakeProc:
    def __init__(self, rc: int = 0, stderr: bytes = b"") -> None:
        self.returncode = rc
        self._stderr = stderr

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return b"", self._stderr

    def kill(self) -> None:  # pragma: no cover
        pass


def _patch_subprocess(rc: int = 0, stderr: bytes = b""):
    captured: list[list[str]] = []
    stdin_seen: list[bytes | None] = []

    async def _fake(*argv, **kw):
        captured.append(list(argv))
        proc = _FakeProc(rc, stderr)
        orig = proc.communicate

        async def communicate(input: bytes | None = None) -> tuple[bytes, bytes]:
            stdin_seen.append(input)
            return await orig(None)
        proc.communicate = communicate  # type: ignore[assignment]
        return proc

    return patch.object(asyncio, "create_subprocess_exec", _fake), captured, stdin_seen


@pytest.mark.asyncio
async def test_write_file_emits_correct_docker_argv_and_sh_script() -> None:
    patcher, captured, stdin_seen = _patch_subprocess(rc=0)
    with patcher:
        success, error = await write_file_to_container(
            "web1-ssh", "/etc/secrets.json", b'{"key":"value"}',
            mode=0o600,
        )
    assert success is True and error is None
    argv = captured[0]
    assert argv[:4] == ["docker", "exec", "-i", "web1-ssh"]
    assert argv[4:6] == ["sh", "-c"]
    script = argv[6]
    # Composed in fixed order: mkdir -p, base64 -d > path, chmod, [touch].
    assert "mkdir -p /etc" in script
    assert "base64 -d > /etc/secrets.json" in script
    assert "chmod 600 /etc/secrets.json" in script
    # Without explicit mtime, no touch -d is emitted.
    assert "touch -d" not in script
    # Stdin carries the base64 payload — never the argv (ARG_MAX safety).
    assert stdin_seen[0] == base64.b64encode(b'{"key":"value"}')


@pytest.mark.asyncio
async def test_write_file_round_trips_arbitrary_binary() -> None:
    patcher, _captured, stdin_seen = _patch_subprocess(rc=0)
    payload = bytes(range(256)) * 8  # 2 KB of every byte value
    with patcher:
        success, _err = await write_file_to_container(
            "web1-ssh", "/tmp/bin.dat", payload,
        )
    assert success is True
    assert base64.b64decode(stdin_seen[0]) == payload


@pytest.mark.asyncio
async def test_write_file_backdates_mtime_via_iso_touch() -> None:
    patcher, captured, _stdin = _patch_subprocess(rc=0)
    mtime = datetime(2026, 4, 20, 11, 30, 0, tzinfo=timezone.utc)
    with patcher:
        await write_file_to_container(
            "web1-ssh", "/etc/x.conf", b"hello", mtime=mtime,
        )
    script = captured[0][6]
    assert "touch -d '2026-04-20 11:30:00 UTC' /etc/x.conf" in script


@pytest.mark.asyncio
async def test_write_file_returns_failure_with_stderr_on_nonzero_rc() -> None:
    patcher, _captured, _stdin = _patch_subprocess(rc=125, stderr=b"container down")
    with patcher:
        success, error = await write_file_to_container(
            "web1-ssh", "/etc/x.conf", b"y",
        )
    assert success is False
    assert error and "container down" in error


@pytest.mark.asyncio
async def test_write_file_rejects_empty_path() -> None:
    success, error = await write_file_to_container(
        "web1-ssh", "", b"y",
    )
    assert success is False and error == "empty path"


@pytest.mark.asyncio
async def test_delete_file_emits_rm_minus_f() -> None:
    patcher, captured, _stdin = _patch_subprocess(rc=0)
    with patcher:
        success, _err = await delete_file_from_container(
            "web1-ssh", "/etc/secrets.json",
        )
    assert success is True
    argv = captured[0]
    assert argv[:3] == ["docker", "exec", "web1-ssh"]
    assert "rm -f /etc/secrets.json" in argv[5]


@pytest.mark.asyncio
async def test_delete_file_returns_failure_on_docker_error() -> None:
    patcher, _captured, _stdin = _patch_subprocess(rc=1, stderr=b"oops")
    with patcher:
        success, error = await delete_file_from_container(
            "web1-ssh", "/etc/x.conf",
        )
    assert success is False and error == "oops"
