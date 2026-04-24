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
    """Point `_deploy_root()` at a faked deploy tree under tmp_path.

    Services are Jinja2 templates keyed on ``{{ install_dir }}`` —
    matching production layout since the refactor that made install
    path configurable.
    """
    deploy = tmp_path / "deploy"
    (deploy / "polkit").mkdir(parents=True)
    (deploy / "tmpfiles.d").mkdir()
    (deploy / "decnet-bus.service.j2").write_text(
        "[Service]\nExecStart={{ install_dir }}/venv/bin/decnet bus\n"
    )
    (deploy / "decnet-api.service.j2").write_text(
        "[Service]\nWorkingDirectory={{ install_dir }}\n"
        "ExecStart={{ install_dir }}/venv/bin/decnet api\n"
    )
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


def test_init_writes_decnet_ini_not_config_ini(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, missing_user_and_group: None,
) -> None:
    """Placeholder target is /etc/decnet/decnet.ini (new name) — matches
    what decnet.config_ini.load_ini_config() actually reads. Guards
    against regressing to the old `config.ini` name."""
    _seed_deploy(monkeypatch, tmp_path)
    prefix = tmp_path / "root"
    r = runner.invoke(app, ["init", "--no-start", "--prefix", str(prefix)])
    assert r.exit_code == 0, r.output

    ini = prefix / "etc/decnet/decnet.ini"
    legacy = prefix / "etc/decnet/config.ini"
    assert ini.is_file(), "decnet.ini should be written"
    assert not legacy.exists(), "legacy config.ini must not be written"

    body = ini.read_text()
    # Admin-facing sections are documented as commented examples so
    # the placeholder teaches the file shape.
    for header in ("[decnet]", "[api]", "[web]", "[database]",
                   "[bus]", "[swarm]", "[logging]", "[ingester]",
                   "[tracing]", "[agent]"):
        assert header in body, f"placeholder missing {header} example"


def test_install_dir_renders_into_service_units(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, missing_user_and_group: None,
) -> None:
    """`--install-dir /srv/decnet` must land in the rendered service
    files. Regression guard for the Jinja2 templating refactor."""
    _seed_deploy(monkeypatch, tmp_path)
    prefix = tmp_path / "root"
    r = runner.invoke(
        app,
        [
            "init", "--no-start",
            "--prefix", str(prefix),
            "--install-dir", "/srv/decnet",
        ],
    )
    assert r.exit_code == 0, r.output

    api_unit = prefix / "etc/systemd/system" / "decnet-api.service"
    bus_unit = prefix / "etc/systemd/system" / "decnet-bus.service"
    assert api_unit.is_file()
    api_text = api_unit.read_text()
    assert "/srv/decnet" in api_text
    assert "/opt/decnet" not in api_text
    assert "{{" not in api_text, "unrendered Jinja tag leaked through"
    assert "/srv/decnet" in bus_unit.read_text()

    # useradd --home-dir must match the install_dir override too.
    useradds = [c for c in subprocess_calls if c and c[0] == "useradd"]
    assert useradds, "expected useradd call"
    assert "/srv/decnet" in useradds[0]
    assert "/opt/decnet" not in useradds[0]

    # And /srv/decnet on disk should be the dir we created.
    assert (prefix / "srv/decnet").is_dir()
    assert not (prefix / "opt/decnet").exists()


def test_install_dir_defaults_to_opt(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    """Default --install-dir is /opt/decnet — existing installs remain
    byte-identical with no explicit flag."""
    _seed_deploy(monkeypatch, tmp_path)
    prefix = tmp_path / "root"
    r = runner.invoke(app, ["init", "--no-start", "--prefix", str(prefix)])
    assert r.exit_code == 0, r.output
    api_unit = prefix / "etc/systemd/system" / "decnet-api.service"
    assert "/opt/decnet" in api_unit.read_text()


def test_install_dir_rejects_relative_path(
    monkeypatch: Any, tmp_path: Path,
    no_missing_tools: None, missing_user_and_group: None,
) -> None:
    """Relative install_dir would break every absolute path in a
    rendered service. Reject at the CLI boundary with a clear message."""
    _seed_deploy(monkeypatch, tmp_path)
    r = runner.invoke(
        app,
        [
            "init", "--no-start",
            "--prefix", str(tmp_path / "root"),
            "--install-dir", "relative/path",
        ],
    )
    assert r.exit_code == 1
    assert "must be absolute" in r.output


def test_install_dir_custom_idempotent_second_run(
    monkeypatch: Any, tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    """Rendering the same templates twice with the same context must
    produce byte-identical output — second run SKIPs, no churn."""
    _seed_deploy(monkeypatch, tmp_path)
    prefix = tmp_path / "root"
    runner.invoke(
        app,
        [
            "init", "--no-start",
            "--prefix", str(prefix),
            "--install-dir", "/srv/decnet",
        ],
    )
    r2 = runner.invoke(
        app,
        [
            "init", "--no-start",
            "--prefix", str(prefix),
            "--install-dir", "/srv/decnet",
        ],
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


def _seed_installed_state(prefix: Path) -> None:
    """Create the files a prior `decnet init` would have installed."""
    systemd = prefix / "etc/systemd/system"
    systemd.mkdir(parents=True)
    (systemd / "decnet-bus.service").write_text("# bus\n")
    (systemd / "decnet-api.service").write_text("# api\n")
    (systemd / "decnet.target").write_text("# target\n")
    polkit = prefix / "etc/polkit-1/rules.d"
    polkit.mkdir(parents=True)
    (polkit / "50-decnet-workers.rules").write_text("// rule\n")
    tmpfiles = prefix / "etc/tmpfiles.d"
    tmpfiles.mkdir(parents=True)
    (tmpfiles / "decnet.conf").write_text("d /run/decnet\n")
    etc_decnet = prefix / "etc/decnet"
    etc_decnet.mkdir(parents=True)
    (etc_decnet / "decnet.ini").write_text("[decnet]\n")
    # Also seed the legacy config.ini so we cover the legacy-cleanup path.
    (etc_decnet / "config.ini").write_text("[decnet]\n")
    (prefix / "opt/decnet").mkdir(parents=True)
    (prefix / "run/decnet").mkdir(parents=True)
    (prefix / "var/lib/decnet").mkdir(parents=True)
    (prefix / "var/log/decnet").mkdir(parents=True)
    (prefix / "var/log/decnet/events.jsonl").write_text("{}\n")


def test_deinit_removes_units_polkit_tmpfiles_and_preserves_data(
    tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    prefix = tmp_path / "root"
    _seed_installed_state(prefix)
    result = runner.invoke(
        app, ["init", "--deinit", "--prefix", str(prefix)],
    )
    assert result.exit_code == 0, result.output

    # Units + polkit + tmpfiles.d gone.
    assert not (prefix / "etc/systemd/system/decnet-bus.service").exists()
    assert not (prefix / "etc/systemd/system/decnet.target").exists()
    assert not (prefix / "etc/polkit-1/rules.d/50-decnet-workers.rules").exists()
    assert not (prefix / "etc/tmpfiles.d/decnet.conf").exists()
    assert not (prefix / "etc/decnet").exists()
    assert not (prefix / "opt/decnet").exists()

    # Data dirs preserved.
    assert (prefix / "var/lib/decnet").exists()
    assert (prefix / "var/log/decnet/events.jsonl").read_text() == "{}\n"

    # systemctl disable + daemon-reload invoked.
    assert ["systemctl", "disable", "--now", "decnet.target"] in subprocess_calls
    assert ["systemctl", "daemon-reload"] in subprocess_calls
    # User / group are PRESERVED without --purge — an operator who
    # passed --user $USER during dev must not lose their login account.
    assert ["userdel", "decnet"] not in subprocess_calls
    assert ["groupdel", "decnet"] not in subprocess_calls


def test_deinit_purge_wipes_data_dirs(
    tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    prefix = tmp_path / "root"
    _seed_installed_state(prefix)
    result = runner.invoke(
        app, ["init", "--deinit", "--purge", "--prefix", str(prefix)],
    )
    assert result.exit_code == 0, result.output
    assert not (prefix / "var/lib/decnet").exists()
    assert not (prefix / "var/log/decnet").exists()
    # --purge also removes the service user/group.
    assert ["userdel", "decnet"] in subprocess_calls
    assert ["groupdel", "decnet"] in subprocess_calls


def test_deinit_is_idempotent_on_clean_host(
    tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, missing_user_and_group: None,
) -> None:
    prefix = tmp_path / "root"
    # Nothing seeded — everything should SKIP.
    result = runner.invoke(
        app, ["init", "--deinit", "--prefix", str(prefix)],
    )
    assert result.exit_code == 0, result.output
    assert result.output.count("[SKIP]") >= 5
    # userdel / groupdel never invoked because user/group are absent.
    assert ["userdel", "decnet"] not in subprocess_calls
    assert ["groupdel", "decnet"] not in subprocess_calls


def test_deinit_dry_run_touches_nothing(
    tmp_path: Path, subprocess_calls: List[List[str]],
    no_missing_tools: None, present_user_and_group: None,
) -> None:
    prefix = tmp_path / "root"
    _seed_installed_state(prefix)
    result = runner.invoke(
        app,
        ["init", "--deinit", "--purge", "--dry-run", "--prefix", str(prefix)],
    )
    assert result.exit_code == 0, result.output
    assert subprocess_calls == []
    assert (prefix / "etc/systemd/system/decnet.target").exists()
    assert (prefix / "var/lib/decnet").exists()


def test_purge_without_deinit_errors(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["init", "--purge", "--prefix", str(tmp_path / "root")],
    )
    assert result.exit_code == 1
    assert "--purge only applies with --deinit" in result.output


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
