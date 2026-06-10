# SPDX-License-Identifier: AGPL-3.0-or-later
"""Updater executor: directory rotation, probe-driven rollback, safety checks.

All three real seams (`_run_pip`, `_spawn_agent`, `_stop_agent`,
`_probe_agent`) are monkeypatched so these tests never shell out or
touch a real Python venv. The rotation/symlink/extract logic is exercised
against a ``tmp_path`` install dir.
"""
from __future__ import annotations

import hashlib
import io
import pathlib
import subprocess
import tarfile
from typing import Any

import pytest

from decnet.updater import executor as ex


# ------------------------------------------------------------------ helpers

def _make_tarball(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _digest(tarball: bytes) -> str:
    """SHA-256 hex of the tarball — now mandatory on run_update/run_update_self."""
    return hashlib.sha256(tarball).hexdigest()


class _PipOK:
    returncode = 0
    stdout = ""
    stderr = ""


class _PipFail:
    returncode = 1
    stdout = ""
    stderr = "resolver error: Could not find a version that satisfies ..."


@pytest.fixture
def install_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "decnet"
    d.mkdir()
    (d / "releases").mkdir()
    return d


@pytest.fixture
def agent_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "agent"
    d.mkdir()
    # executor._probe_agent checks these exist before constructing SSL ctx,
    # but the probe seam is monkeypatched in every test so content doesn't
    # matter — still create them so the non-stubbed path is representative.
    (d / "ca.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
    (d / "worker.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
    (d / "worker.key").write_bytes(b"-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n")
    return d


@pytest.fixture
def seed_existing_release(install_dir: pathlib.Path) -> None:
    """Pretend an install is already live: create releases/active with a marker."""
    active = install_dir / "releases" / "active"
    active.mkdir()
    (active / "marker.txt").write_text("old")
    ex._write_manifest(active, sha="OLDSHA")
    # current -> active
    ex._point_current_at(install_dir, active)


# --------------------------------------------------------- extract + safety

def test_extract_rejects_path_traversal(tmp_path: pathlib.Path) -> None:
    evil = _make_tarball({"../escape.txt": "pwned"})
    with pytest.raises(ex.UpdateError, match="unsafe path"):
        ex.extract_tarball(evil, tmp_path / "out")


def test_extract_rejects_absolute_paths(tmp_path: pathlib.Path) -> None:
    evil = _make_tarball({"/etc/passwd": "root:x:0:0"})
    with pytest.raises(ex.UpdateError, match="unsafe path"):
        ex.extract_tarball(evil, tmp_path / "out")


def test_extract_happy_path(tmp_path: pathlib.Path) -> None:
    tb = _make_tarball({"a/b.txt": "hello"})
    out = tmp_path / "out"
    ex.extract_tarball(tb, out)
    assert (out / "a" / "b.txt").read_text() == "hello"


def _tarball_with_link(linkname: str, target: str, *, hard: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=linkname)
        info.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
        info.linkname = target
        tar.addfile(info)
    return buf.getvalue()


def test_extract_rejects_symlinks(tmp_path: pathlib.Path) -> None:
    evil = _tarball_with_link("link.txt", "/etc/passwd")
    with pytest.raises(ex.UpdateError, match="only regular files"):
        ex.extract_tarball(evil, tmp_path / "out")


def test_extract_rejects_hardlinks(tmp_path: pathlib.Path) -> None:
    evil = _tarball_with_link("link.txt", "real.txt", hard=True)
    with pytest.raises(ex.UpdateError, match="only regular files"):
        ex.extract_tarball(evil, tmp_path / "out")


def test_extract_rejects_device_nodes(tmp_path: pathlib.Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="dev_null")
        info.type = tarfile.CHRTYPE
        info.devmajor = 1
        info.devminor = 3
        tar.addfile(info)
    with pytest.raises(ex.UpdateError, match="only regular files"):
        ex.extract_tarball(buf.getvalue(), tmp_path / "out")


def test_extract_rejects_oversized_tarball(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Lower the cap rather than building a 256 MiB tarball in memory.
    monkeypatch.setattr(ex, "MAX_TARBALL_UNCOMPRESSED_BYTES", 32)
    big = _make_tarball({"big.txt": "x" * 64})
    with pytest.raises(ex.UpdateError, match="exceeds size cap"):
        ex.extract_tarball(big, tmp_path / "out")


def test_extract_strips_setuid_bit(tmp_path: pathlib.Path) -> None:
    buf = io.BytesIO()
    payload = b"hello"
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="suid.bin")
        info.size = len(payload)
        info.mode = 0o4755  # setuid + rwxr-xr-x
        tar.addfile(info, io.BytesIO(payload))
    out = tmp_path / "out"
    ex.extract_tarball(buf.getvalue(), out)
    mode = (out / "suid.bin").stat().st_mode & 0o7777
    assert mode & 0o4000 == 0, f"setuid bit should be stripped, got {oct(mode)}"


# ----------------------------------------------------------- sha256 verify

def test_run_update_rejects_sha256_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
) -> None:
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: None)
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 1)
    monkeypatch.setattr(ex, "_probe_agent", lambda **_: (True, "ok"))
    tb = _make_tarball({"marker.txt": "new"})
    bad = "0" * 64
    with pytest.raises(ex.UpdateError, match="sha256 mismatch"):
        ex.run_update(
            tb, sha="S", install_dir=install_dir, agent_dir=agent_dir,
            expected_sha256=bad,
        )
    # Mismatch must abort before staging is left around.
    assert not (install_dir / "releases" / "active.new").exists()


def test_run_update_accepts_correct_sha256(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
) -> None:
    import hashlib as _hl
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: None)
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 1)
    monkeypatch.setattr(ex, "_probe_agent", lambda **_: (True, "ok"))
    tb = _make_tarball({"marker.txt": "new"})
    digest = _hl.sha256(tb).hexdigest()
    result = ex.run_update(
        tb, sha="S", install_dir=install_dir, agent_dir=agent_dir,
        expected_sha256=digest,
    )
    assert result["status"] == "updated"


def test_run_update_rejects_malformed_sha256(
    install_dir: pathlib.Path, agent_dir: pathlib.Path,
) -> None:
    tb = _make_tarball({"x.txt": "y"})
    with pytest.raises(ex.UpdateError, match="not a 64-char hex"):
        ex.run_update(
            tb, sha="S", install_dir=install_dir, agent_dir=agent_dir,
            expected_sha256="not-a-hex-digest",
        )


@pytest.mark.parametrize("missing", ["", "   ", None])
def test_run_update_rejects_missing_sha256_fail_closed(
    install_dir: pathlib.Path, agent_dir: pathlib.Path, missing: Any,
) -> None:
    """V12.1.2 fail-closed: an absent/empty digest is rejected BEFORE any
    extraction or pip-install. No staging tree is produced."""
    tb = _make_tarball({"x.txt": "y"})
    with pytest.raises(ex.UpdateError, match="required but was missing or empty"):
        ex.run_update(
            tb, sha="S", expected_sha256=missing,  # type: ignore[arg-type]
            install_dir=install_dir, agent_dir=agent_dir,
        )
    assert not (install_dir / "releases" / "active.new").exists()


@pytest.mark.parametrize("missing", ["", "   ", None])
def test_run_update_self_rejects_missing_sha256_fail_closed(
    install_dir: pathlib.Path, missing: Any,
) -> None:
    active = install_dir / "releases" / "active"
    active.mkdir()
    (active / "marker").write_text("old-updater")
    tb = _make_tarball({"marker": "new-updater"})
    with pytest.raises(ex.UpdateError, match="required but was missing or empty"):
        ex.run_update_self(
            tb, sha="U", updater_install_dir=install_dir,
            expected_sha256=missing,  # type: ignore[arg-type]
            exec_cb=lambda a: None,
        )
    # Active untouched, nothing staged.
    assert (install_dir / "releases" / "active" / "marker").read_text() == "old-updater"
    assert not (install_dir / "releases" / "active.new").exists()


def test_clean_stale_staging(install_dir: pathlib.Path) -> None:
    staging = install_dir / "releases" / "active.new"
    staging.mkdir()
    (staging / "junk").write_text("left from a crash")
    ex.clean_stale_staging(install_dir)
    assert not staging.exists()


# ---------------------------------------------------------------- happy path

def test_update_rotates_and_probes(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
    seed_existing_release: None,
) -> None:
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: None)
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 42)
    monkeypatch.setattr(ex, "_probe_agent", lambda **_: (True, "ok"))

    tb = _make_tarball({"marker.txt": "new"})
    result = ex.run_update(tb, sha="NEWSHA", expected_sha256=_digest(tb), install_dir=install_dir, agent_dir=agent_dir)

    assert result["status"] == "updated"
    assert result["release"]["sha"] == "NEWSHA"
    assert (install_dir / "releases" / "active" / "marker.txt").read_text() == "new"
    # Old release demoted, not deleted.
    assert (install_dir / "releases" / "prev" / "marker.txt").read_text() == "old"
    # Current symlink points at the new active.
    assert (install_dir / "current").resolve() == (install_dir / "releases" / "active").resolve()


def test_update_first_install_without_previous(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
) -> None:
    """No existing active/ dir — first real install via the updater."""
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: None)
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 1)
    monkeypatch.setattr(ex, "_probe_agent", lambda **_: (True, "ok"))

    tb = _make_tarball({"marker.txt": "first"})
    result = ex.run_update(tb, sha="S1", expected_sha256=_digest(tb), install_dir=install_dir, agent_dir=agent_dir)
    assert result["status"] == "updated"
    assert not (install_dir / "releases" / "prev").exists()


# ------------------------------------------------------------ pip failure

def test_update_pip_failure_aborts_before_rotation(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
    seed_existing_release: None,
) -> None:
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipFail())
    stop_called: list[bool] = []
    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: stop_called.append(True))
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 1)
    monkeypatch.setattr(ex, "_probe_agent", lambda **_: (True, "ok"))

    tb = _make_tarball({"marker.txt": "new"})
    with pytest.raises(ex.UpdateError, match="pip install failed") as ei:
        ex.run_update(tb, sha="S", expected_sha256=_digest(tb), install_dir=install_dir, agent_dir=agent_dir)
    assert "resolver error" in ei.value.stderr

    # Nothing rotated — old active still live, no prev created.
    assert (install_dir / "releases" / "active" / "marker.txt").read_text() == "old"
    assert not (install_dir / "releases" / "prev").exists()
    # Agent never touched.
    assert stop_called == []
    # Staging cleaned up.
    assert not (install_dir / "releases" / "active.new").exists()


# ------------------------------------------------------------ probe failure

def test_update_probe_failure_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
    seed_existing_release: None,
) -> None:
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: None)
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 1)

    calls: list[int] = [0]

    def _probe(**_: Any) -> tuple[bool, str]:
        calls[0] += 1
        if calls[0] == 1:
            return False, "connection refused"
        return True, "ok"  # rollback probe succeeds

    monkeypatch.setattr(ex, "_probe_agent", _probe)

    tb = _make_tarball({"marker.txt": "new"})
    with pytest.raises(ex.UpdateError, match="health probe") as ei:
        ex.run_update(tb, sha="NEWSHA", expected_sha256=_digest(tb), install_dir=install_dir, agent_dir=agent_dir)
    assert ei.value.rolled_back is True
    assert "connection refused" in ei.value.stderr

    # Rolled back: active has the old marker again.
    assert (install_dir / "releases" / "active" / "marker.txt").read_text() == "old"
    # Prev now holds what would have been the new release.
    assert (install_dir / "releases" / "prev" / "marker.txt").read_text() == "new"
    # Current symlink points back at active.
    assert (install_dir / "current").resolve() == (install_dir / "releases" / "active").resolve()


# ------------------------------------------------------------ manual rollback

def test_manual_rollback_swaps(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
    seed_existing_release: None,
) -> None:
    # Seed a prev/ so rollback has somewhere to go.
    prev = install_dir / "releases" / "prev"
    prev.mkdir()
    (prev / "marker.txt").write_text("older")
    ex._write_manifest(prev, sha="OLDERSHA")

    monkeypatch.setattr(ex, "_stop_agent", lambda *a, **k: None)
    monkeypatch.setattr(ex, "_spawn_agent", lambda *a, **k: 1)
    monkeypatch.setattr(ex, "_probe_agent", lambda **_: (True, "ok"))

    result = ex.run_rollback(install_dir=install_dir, agent_dir=agent_dir)
    assert result["status"] == "rolled_back"
    assert (install_dir / "releases" / "active" / "marker.txt").read_text() == "older"
    assert (install_dir / "releases" / "prev" / "marker.txt").read_text() == "old"


def test_manual_rollback_refuses_without_prev(
    install_dir: pathlib.Path,
    seed_existing_release: None,
) -> None:
    with pytest.raises(ex.UpdateError, match="no previous release"):
        ex.run_rollback(install_dir=install_dir)


# ---------------------------------------------------------------- releases

def test_list_releases_includes_only_existing_slots(
    install_dir: pathlib.Path,
    seed_existing_release: None,
) -> None:
    rs = ex.list_releases(install_dir)
    assert [r.slot for r in rs] == ["active"]
    assert rs[0].sha == "OLDSHA"


# ---------------------------------------------------------------- self-update

def test_update_self_rotates_and_calls_exec_cb(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    # Seed a stand-in "active" for the updater itself.
    active = install_dir / "releases" / "active"
    active.mkdir()
    (active / "marker").write_text("old-updater")

    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    seen_argv: list[list[str]] = []

    tb = _make_tarball({"marker": "new-updater"})
    result = ex.run_update_self(
        tb, sha="USHA", updater_install_dir=install_dir,
        expected_sha256=_digest(tb),
        exec_cb=lambda argv: seen_argv.append(argv),
    )
    assert result["status"] == "self_update_queued"
    assert (install_dir / "releases" / "active" / "marker").read_text() == "new-updater"
    assert (install_dir / "releases" / "prev" / "marker").read_text() == "old-updater"
    assert len(seen_argv) == 1
    assert "updater" in seen_argv[0]


def test_update_self_under_systemd_defers_to_systemctl(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    """Under systemd, update-self must NOT os.execv — it hands the restart
    to systemd so the new process inherits the unit context. A detached
    ``systemctl restart decnet-updater.service`` is scheduled after a short
    sleep so the HTTP response can flush before the unit cycles."""
    active = install_dir / "releases" / "active"
    active.mkdir()
    (active / "marker").write_text("old-updater")
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipOK())
    monkeypatch.setattr(ex, "_systemd_available", lambda: True)

    popen_calls: list[list[str]] = []
    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            popen_calls.append(cmd)
    monkeypatch.setattr(ex.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(ex.os, "execv", lambda *a, **k: pytest.fail("execv taken under systemd"))

    tb = _make_tarball({"marker": "new-updater"})
    result = ex.run_update_self(tb, sha="USHA", updater_install_dir=install_dir, expected_sha256=_digest(tb))
    assert result == {"status": "self_update_queued", "via": "systemd"}
    assert len(popen_calls) == 1
    sh_cmd = popen_calls[0]
    assert sh_cmd[:2] == ["sh", "-c"]
    assert "systemctl restart decnet-updater.service" in sh_cmd[2]


def test_update_self_pip_failure_leaves_active_intact(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    active = install_dir / "releases" / "active"
    active.mkdir()
    (active / "marker").write_text("old-updater")
    monkeypatch.setattr(ex, "_run_pip", lambda release: _PipFail())

    tb = _make_tarball({"marker": "new-updater"})
    with pytest.raises(ex.UpdateError, match="pip install failed"):
        ex.run_update_self(tb, sha="U", updater_install_dir=install_dir, expected_sha256=_digest(tb), exec_cb=lambda a: None)
    assert (install_dir / "releases" / "active" / "marker").read_text() == "old-updater"
    assert not (install_dir / "releases" / "active.new").exists()


def test_stop_agent_falls_back_to_proc_scan_when_no_pidfile(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    """No agent.pid → _stop_agent still terminates agents found via /proc."""
    killed: list[tuple[int, int]] = []

    def fake_kill(pid: int, sig: int) -> None:
        killed.append((pid, sig))
        raise ProcessLookupError  # pretend it already died after SIGTERM

    monkeypatch.setattr(ex, "_systemd_available", lambda: False)
    monkeypatch.setattr(ex, "_discover_agent_pids", lambda: [4242, 4243])
    monkeypatch.setattr(ex.os, "kill", fake_kill)

    assert not (install_dir / "agent.pid").exists()
    ex._stop_agent(install_dir, grace=0.0)

    import signal as _signal
    assert (4242, _signal.SIGTERM) in killed
    assert (4243, _signal.SIGTERM) in killed


def test_systemd_available_requires_invocation_id_and_systemctl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both INVOCATION_ID and a resolvable systemctl are needed."""
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    assert ex._systemd_available() is False

    monkeypatch.setenv("INVOCATION_ID", "abc")
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert ex._systemd_available() is False

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/systemctl")
    assert ex._systemd_available() is True


def test_spawn_agent_dispatches_to_systemd_when_available(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    monkeypatch.setattr(ex, "_systemd_available", lambda: True)
    called: list[pathlib.Path] = []
    monkeypatch.setattr(ex, "_spawn_agent_via_systemd", lambda d: called.append(d) or 999)
    monkeypatch.setattr(ex, "_spawn_agent_via_popen", lambda d: pytest.fail("popen path taken"))
    assert ex._spawn_agent(install_dir) == 999
    assert called == [install_dir]


def test_spawn_agent_dispatches_to_popen_when_not_systemd(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    monkeypatch.setattr(ex, "_systemd_available", lambda: False)
    monkeypatch.setattr(ex, "_spawn_agent_via_systemd", lambda d: pytest.fail("systemd path taken"))
    monkeypatch.setattr(ex, "_spawn_agent_via_popen", lambda d: 777)
    assert ex._spawn_agent(install_dir) == 777


def test_stop_agent_is_noop_under_systemd(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    """Under systemd, stop is skipped — systemctl restart handles it atomically."""
    monkeypatch.setattr(ex, "_systemd_available", lambda: True)
    monkeypatch.setattr(ex, "_discover_agent_pids", lambda: pytest.fail("scanned /proc"))
    monkeypatch.setattr(ex.os, "kill", lambda *a, **k: pytest.fail("sent signal"))
    (install_dir / "agent.pid").write_text("12345")
    ex._stop_agent(install_dir, grace=0.0)  # must not raise


def test_spawn_agent_via_systemd_records_main_pid(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    calls: list[list[str]] = []

    class _Out:
        def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
            self.stdout = stdout
            self.returncode = returncode
            self.stderr = stderr

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(cmd)
        if "show" in cmd:
            return _Out("4711\n")
        return _Out("")

    monkeypatch.setattr(ex.subprocess, "run", fake_run)
    pid = ex._spawn_agent_via_systemd(install_dir)
    assert pid == 4711
    assert (install_dir / "agent.pid").read_text() == "4711"
    # Agent restart, forwarder restart, each aux microservice, then the
    # MainPID lookup on the agent.
    assert calls[0] == ["systemctl", "restart", ex.AGENT_SYSTEMD_UNIT]
    assert calls[1] == ["systemctl", "restart", ex.FORWARDER_SYSTEMD_UNIT]
    aux_calls = calls[2 : 2 + len(ex.AUXILIARY_SYSTEMD_UNITS)]
    assert aux_calls == [
        ["systemctl", "restart", unit] for unit in ex.AUXILIARY_SYSTEMD_UNITS
    ]
    show_call = calls[2 + len(ex.AUXILIARY_SYSTEMD_UNITS)]
    assert show_call[:2] == ["systemctl", "show"]
    assert ex.AGENT_SYSTEMD_UNIT in show_call


def test_spawn_agent_via_systemd_tolerates_missing_forwarder_unit(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
) -> None:
    """Legacy enrollments lack decnet-forwarder.service — restart fails and
    must not abort the update."""
    class _Out:
        def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
            self.stdout = stdout
            self.returncode = returncode
            self.stderr = stderr

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        if "restart" in cmd and ex.FORWARDER_SYSTEMD_UNIT in cmd:
            return _Out(returncode=5, stderr="Unit not found.")
        if "show" in cmd:
            return _Out("4711\n")
        return _Out("")

    monkeypatch.setattr(ex.subprocess, "run", fake_run)
    pid = ex._spawn_agent_via_systemd(install_dir)
    assert pid == 4711


# ---------------------------------------------------------- _sync_systemd_units

def _make_release_with_units(install_dir: pathlib.Path, units: dict[str, str]) -> None:
    src = install_dir / "releases" / "active" / "etc" / "systemd" / "system"
    src.mkdir(parents=True)
    for name, body in units.items():
        (src / name).write_text(body)


def test_sync_systemd_units_copies_new_files_and_reloads(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    """Shipping a new unit or changing an existing one triggers a single
    daemon-reload after the file writes."""
    _make_release_with_units(install_dir, {
        "decnet-collector.service": "unit-body-v1\n",
        "decnet-agent.service": "unit-body-agent\n",
    })
    dst_root = tmp_path / "etc-systemd"
    dst_root.mkdir()
    (dst_root / "decnet-agent.service").write_text("unit-body-agent-OLD\n")

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setenv("INVOCATION_ID", "x")
    monkeypatch.setattr(ex.subprocess, "run", fake_run)

    changed = ex._sync_systemd_units(install_dir, dst_root=dst_root)
    assert changed is True
    assert (dst_root / "decnet-collector.service").read_text() == "unit-body-v1\n"
    assert (dst_root / "decnet-agent.service").read_text() == "unit-body-agent\n"
    assert calls == [["systemctl", "daemon-reload"]]


def test_sync_systemd_units_noop_when_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    install_dir: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    _make_release_with_units(install_dir, {"decnet-agent.service": "same\n"})
    dst_root = tmp_path / "etc-systemd"
    dst_root.mkdir()
    (dst_root / "decnet-agent.service").write_text("same\n")

    calls: list[list[str]] = []
    monkeypatch.setenv("INVOCATION_ID", "x")
    monkeypatch.setattr(
        ex.subprocess, "run",
        lambda cmd, **_: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""),
    )

    changed = ex._sync_systemd_units(install_dir, dst_root=dst_root)
    assert changed is False
    assert calls == []  # no daemon-reload when nothing changed


def test_sync_systemd_units_missing_src_is_noop(
    install_dir: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    """Legacy bundles without etc/systemd/system in the release: no-op."""
    (install_dir / "releases" / "active").mkdir(parents=True)
    assert ex._sync_systemd_units(install_dir, dst_root=tmp_path) is False
