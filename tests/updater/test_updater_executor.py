"""Updater executor: directory rotation, probe-driven rollback, safety checks.

All three real seams (`_run_pip`, `_spawn_agent`, `_stop_agent`,
`_probe_agent`) are monkeypatched so these tests never shell out or
touch a real Python venv. The rotation/symlink/extract logic is exercised
against a ``tmp_path`` install dir.
"""
from __future__ import annotations

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
    result = ex.run_update(tb, sha="NEWSHA", install_dir=install_dir, agent_dir=agent_dir)

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
    result = ex.run_update(tb, sha="S1", install_dir=install_dir, agent_dir=agent_dir)
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
        ex.run_update(tb, sha="S", install_dir=install_dir, agent_dir=agent_dir)
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
        ex.run_update(tb, sha="NEWSHA", install_dir=install_dir, agent_dir=agent_dir)
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
        exec_cb=lambda argv: seen_argv.append(argv),
    )
    assert result["status"] == "self_update_queued"
    assert (install_dir / "releases" / "active" / "marker").read_text() == "new-updater"
    assert (install_dir / "releases" / "prev" / "marker").read_text() == "old-updater"
    assert len(seen_argv) == 1
    assert "updater" in seen_argv[0]


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
        ex.run_update_self(tb, sha="U", updater_install_dir=install_dir, exec_cb=lambda a: None)
    assert (install_dir / "releases" / "active" / "marker").read_text() == "old-updater"
    assert not (install_dir / "releases" / "active.new").exists()
