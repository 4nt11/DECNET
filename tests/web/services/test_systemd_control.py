"""Unit tests for :mod:`decnet.web.services.systemd_control`.

These tests monkeypatch :func:`asyncio.create_subprocess_exec` so we
never touch real ``systemctl``.  The contract under test is:

* argv shape — ``["systemctl", <verb>, "decnet-<name>.service"]``
* non-zero return ⇒ :class:`SystemctlError` with returncode + stderr
* ``list_installed`` parses ``list-unit-files`` output into a name set
* cache honours the 30s TTL
"""
from __future__ import annotations

import asyncio
from typing import Any, List, Tuple

import pytest

from decnet.web.services import systemd_control as sc


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self) -> Tuple[bytes, bytes]:
        return self._stdout, self._stderr


def _patch_exec(monkeypatch: Any, *, rc: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> List[tuple]:
    calls: List[tuple] = []

    async def fake_exec(*argv: str, **_kwargs: Any) -> _FakeProc:
        calls.append(argv)
        return _FakeProc(rc, stdout, stderr)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return calls


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    sc.reset_cache_for_tests()
    yield
    sc.reset_cache_for_tests()


@pytest.mark.asyncio
async def test_start_builds_correct_argv(monkeypatch: Any) -> None:
    calls = _patch_exec(monkeypatch, rc=0)
    await sc.start("mutator")
    assert calls == [("systemctl", "start", "decnet-mutator.service")]


@pytest.mark.asyncio
async def test_stop_builds_correct_argv(monkeypatch: Any) -> None:
    calls = _patch_exec(monkeypatch, rc=0)
    await sc.stop("sniffer")
    assert calls == [("systemctl", "stop", "decnet-sniffer.service")]


@pytest.mark.asyncio
async def test_start_raises_systemctl_error_on_nonzero(monkeypatch: Any) -> None:
    _patch_exec(monkeypatch, rc=5, stderr=b"Unit decnet-mutator.service not found.\n")
    with pytest.raises(sc.SystemctlError) as exc_info:
        await sc.start("mutator")
    err = exc_info.value
    assert err.returncode == 5
    assert err.unit == "decnet-mutator.service"
    assert "not found" in err.stderr


@pytest.mark.asyncio
async def test_is_active_true_when_stdout_active(monkeypatch: Any) -> None:
    _patch_exec(monkeypatch, rc=0, stdout=b"active\n")
    assert await sc.is_active("bus") is True


@pytest.mark.asyncio
async def test_is_active_false_when_inactive(monkeypatch: Any) -> None:
    # systemctl exits 3 for "inactive" — is_active must treat that as a
    # signal, not an error.
    _patch_exec(monkeypatch, rc=3, stdout=b"inactive\n")
    assert await sc.is_active("bus") is False


@pytest.mark.asyncio
async def test_list_installed_parses_unit_files(monkeypatch: Any) -> None:
    stdout = (
        b"decnet-bus.service         enabled         enabled\n"
        b"decnet-api.service         enabled         enabled\n"
        b"decnet-mutator.service     disabled        enabled\n"
    )
    _patch_exec(monkeypatch, rc=0, stdout=stdout)
    names = await sc.list_installed()
    assert names == {"bus", "api", "mutator"}


@pytest.mark.asyncio
async def test_list_installed_returns_empty_on_failure(monkeypatch: Any) -> None:
    _patch_exec(monkeypatch, rc=1, stderr=b"systemctl: command not found\n")
    names = await sc.list_installed()
    assert names == set()


@pytest.mark.asyncio
async def test_list_installed_is_cached(monkeypatch: Any) -> None:
    stdout = b"decnet-bus.service enabled enabled\n"
    calls = _patch_exec(monkeypatch, rc=0, stdout=stdout)
    await sc.list_installed()
    await sc.list_installed()
    await sc.list_installed()
    # Three logical calls, one real subprocess invocation.
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_list_installed_force_bypasses_cache(monkeypatch: Any) -> None:
    stdout = b"decnet-bus.service enabled enabled\n"
    calls = _patch_exec(monkeypatch, rc=0, stdout=stdout)
    await sc.list_installed()
    await sc.list_installed(force=True)
    assert len(calls) == 2


def test_invalid_worker_name_rejected() -> None:
    with pytest.raises(ValueError):
        sc._unit("../etc/passwd")
    with pytest.raises(ValueError):
        sc._unit("bus.service")
    with pytest.raises(ValueError):
        sc._unit("")
