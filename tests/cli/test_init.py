"""Orchestration tests for ``decnet init``.

The command is a thin orchestrator over privileged system calls.  We
exercise every branch by monkeypatching subprocess + identity lookups
and using the hidden ``--prefix`` option to redirect filesystem writes
into a pytest ``tmp_path``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, List

import pytest
from typer.testing import CliRunner

from decnet.cli import app
from decnet.cli import init as _init


runner = CliRunner()


@pytest.fixture
def subprocess_calls(monkeypatch: Any) -> List[List[str]]:
    calls: List[List[str]] = []

    def _fake_run(argv: List[str], *a: Any, **kw: Any) -> Any:
        calls.append(list(argv))

        class _Ok:
            returncode = 0
        return _Ok()

    monkeypatch.setattr(_init.subprocess, "run", _fake_run)
    return calls


@pytest.fixture
def no_missing_tools(monkeypatch: Any) -> None:
    monkeypatch.setattr(_init.shutil, "which", lambda _: "/usr/bin/fake")


@pytest.fixture
def present_user_and_group(monkeypatch: Any) -> None:
    class _Stub:
        pw_uid = 1000
        gr_gid = 1000

    monkeypatch.setattr(_init.pwd, "getpwnam", lambda _: _Stub())
    monkeypatch.setattr(_init.grp, "getgrnam", lambda _: _Stub())


@pytest.fixture
def missing_user_and_group(monkeypatch: Any) -> None:
    def _raise(_: str) -> None:
        raise KeyError

    monkeypatch.setattr(_init.pwd, "getpwnam", _raise)
    monkeypatch.setattr(_init.grp, "getgrnam", _raise)


def _seed_deploy(monkeypatch: Any, tmp_path: Path) -> Path:
    """Point `_deploy_root()` at a faked deploy tree under tmp_path."""
    deploy = tmp_path / "deploy"
    (deploy / "polkit").mkdir(parents=True)
    (deploy / "tmpfiles.d").mkdir()
    (deploy / "decnet-bus.service").write_text("# bus unit\n")
    (deploy / "decnet-api.service").write_text("# api unit\n")
    (deploy / "decnet.target").write_text("# target\n")
    (deploy / "polkit" / "50-decnet-workers.rules").write_text("// rule\n")
    (deploy / "tmpfiles.d" / "decnet.conf").write_text("d /run/decnet\n")
    monkeypatch.setattr(_init, "_deploy_root", lambda: deploy)
    return deploy


def test_non_root_exits_one(monkeypatch: Any) -> None:
    monkeypatch.setattr(_init.os, "geteuid", lambda: 1000)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 1
    assert "must run as root" in result.output


def test_dry_run_issues_no_subprocess_calls(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, missing_user_and_group: None,
) -> None:
    _seed_deploy(monkeypatch, tmp_path)
    result = runner.invoke(
        app,
        ["init", "--dry-run", "--prefix", str(tmp_path / "root")],
    )
    assert result.exit_code == 0, result.output
    assert subprocess_calls == [], (
        f"dry-run must not exec anything, got {subprocess_calls}"
    )
    assert "would run:" in result.output
    # No real files created either.
    assert not (tmp_path / "root" / "etc/systemd/system").exists()


def test_missing_user_and_group_triggers_useradd_groupadd(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, missing_user_and_group: None,
) -> None:
    _seed_deploy(monkeypatch, tmp_path)
    result = runner.invoke(
        app,
        ["init", "--no-start", "--prefix", str(tmp_path / "root")],
    )
    assert result.exit_code == 0, result.output

    groupadds = [c for c in subprocess_calls if c[:1] == ["groupadd"]]
    useradds = [c for c in subprocess_calls if c[:1] == ["useradd"]]
    assert groupadds == [["groupadd", "--system", "decnet"]]
    assert useradds and useradds[0][:6] == [
        "useradd", "--system", "--gid", "decnet", "--home-dir", "/opt/decnet",
    ]
    assert useradds[0][-1] == "decnet"


def test_present_user_and_group_skipped(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    _seed_deploy(monkeypatch, tmp_path)
    result = runner.invoke(
        app,
        ["init", "--no-start", "--prefix", str(tmp_path / "root")],
    )
    assert result.exit_code == 0, result.output
    assert all(c[0] not in ("groupadd", "useradd") for c in subprocess_calls)
    assert "[SKIP]" in result.output


def test_unit_files_are_installed_then_idempotent(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    _seed_deploy(monkeypatch, tmp_path)
    prefix = tmp_path / "root"
    # First run: installs.
    r1 = runner.invoke(
        app, ["init", "--no-start", "--prefix", str(prefix)],
    )
    assert r1.exit_code == 0, r1.output
    target = prefix / "etc/systemd/system" / "decnet.target"
    assert target.is_file()
    assert target.read_text() == "# target\n"

    # Second run: every copy should SKIP.
    subprocess_calls.clear()
    r2 = runner.invoke(
        app, ["init", "--no-start", "--prefix", str(prefix)],
    )
    assert r2.exit_code == 0, r2.output
    assert "unit files up to date" in r2.output


def test_force_overwrites_existing_units(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    deploy = _seed_deploy(monkeypatch, tmp_path)
    prefix = tmp_path / "root"
    runner.invoke(app, ["init", "--no-start", "--prefix", str(prefix)])
    # Mutate the installed copy so SHA-256 matches source, but we ask
    # for --force anyway: source wins.
    target = prefix / "etc/systemd/system" / "decnet.target"
    target.write_text("# tampered\n")
    r = runner.invoke(
        app,
        ["init", "--no-start", "--force", "--prefix", str(prefix)],
    )
    assert r.exit_code == 0, r.output
    assert target.read_text() == (deploy / "decnet.target").read_text()


def test_no_start_suppresses_target_start(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    _seed_deploy(monkeypatch, tmp_path)
    runner.invoke(
        app,
        ["init", "--no-start", "--prefix", str(tmp_path / "root")],
    )
    enables = [
        c for c in subprocess_calls
        if c[:2] == ["systemctl", "enable"]
    ]
    assert enables == []


def test_default_invokes_target_start(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    _seed_deploy(monkeypatch, tmp_path)
    result = runner.invoke(
        app, ["init", "--prefix", str(tmp_path / "root")],
    )
    assert result.exit_code == 0, result.output
    assert ["systemctl", "enable", "--now", "decnet.target"] in subprocess_calls
    assert ["systemctl", "daemon-reload"] in subprocess_calls


def test_missing_deploy_dir_errors_clearly(monkeypatch: Any, tmp_path: Path) -> None:
    def _boom() -> Path:
        raise RuntimeError("cannot locate deploy/ directory (looked at /nope)")

    monkeypatch.setattr(_init, "_deploy_root", _boom)
    monkeypatch.setattr(_init.shutil, "which", lambda _: "/bin/x")
    result = runner.invoke(
        app, ["init", "--prefix", str(tmp_path / "root")],
    )
    assert result.exit_code == 1
    assert "cannot locate deploy/" in result.output
