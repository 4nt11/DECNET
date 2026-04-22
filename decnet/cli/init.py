"""
`decnet init` — one-shot master-host bootstrap.

Idempotent: running it twice is a no-op on already-configured items.
Takes a freshly ``pip install``'d DECNET and turns it into a ready-to-
run master host: creates the ``decnet`` system user/group, installs
the systemd units + polkit rule + tmpfiles.d entry, seeds the
directory layout, drops a placeholder config, and starts the
``decnet.target`` grouping unit.

Requires root. Uses ``subprocess.run`` (never ``shell=True``) for every
privileged call so the full argv surface is auditable.
"""
from __future__ import annotations

import grp
import hashlib
import os
import pwd
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Callable, List

import typer

import decnet as _decnet_pkg
from .gating import _require_master_mode
from .utils import console, log


_CONFIG_PLACEHOLDER = """\
# /etc/decnet/config.ini — DECNET master-host config.
# Placeholder; reserved for future structured settings.
# Today, most knobs live in /opt/decnet/.env.local as env vars.
[decnet]
"""


def _deploy_root() -> Path:
    """Resolve the on-disk ``deploy/`` directory of the installed package.

    Editable install (``pip install -e .``): sibling of the ``decnet``
    package at repo root. Wheel installs aren't supported yet — the
    error message tells the operator to use an editable install.
    """
    root = Path(_decnet_pkg.__file__).resolve().parent.parent / "deploy"
    if not (root / "decnet.target").is_file():
        raise RuntimeError(
            f"cannot locate deploy/ directory (looked at {root}); "
            "are you on a wheel install that didn't bundle deploy/? "
            "use `pip install -e .` from a git checkout"
        )
    return root


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _run(argv: List[str], *, dry_run: bool) -> None:
    if dry_run:
        console.print(f"  [dim]would run:[/] {' '.join(argv)}")
        return
    log.info("init: exec %s", argv)
    subprocess.run(argv, check=True)  # nosec B603


def _step(label: str, action: Callable[[], str]) -> bool:
    """Run ``action``, print a checklist line.

    The callable returns the human-readable outcome verb:
    ``"ok"`` → ``[ OK ] <label>``,
    ``"skip: <reason>"`` → ``[SKIP] <label> (<reason>)``.
    Any exception becomes ``[FAIL] <label>: <err>`` and re-raises.
    """
    try:
        result = action()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red][FAIL][/] {label}: {exc}")
        raise
    if result.startswith("skip:"):
        reason = result[len("skip:") :].strip()
        console.print(f"[yellow][SKIP][/] {label} ({reason})")
    else:
        console.print(f"[green][ OK ][/] {label}")
    return True


def _ensure_group(group: str, *, dry_run: bool) -> str:
    try:
        grp.getgrnam(group)
        return f"skip: group {group} already exists"
    except KeyError:
        _run(["groupadd", "--system", group], dry_run=dry_run)
        return "ok"


def _ensure_user(user: str, group: str, *, dry_run: bool) -> str:
    try:
        pwd.getpwnam(user)
        return f"skip: user {user} already exists"
    except KeyError:
        _run(
            [
                "useradd", "--system",
                "--gid", group,
                "--home-dir", "/opt/decnet",
                "--shell", "/usr/sbin/nologin",
                "--comment", "DECNET honeypot",
                user,
            ],
            dry_run=dry_run,
        )
        return "ok"


def _ensure_dir(
    path: Path, *, mode: int, owner: str, group: str, dry_run: bool
) -> str:
    existed = path.exists()
    if dry_run:
        console.print(
            f"  [dim]would ensure dir:[/] {path} (mode={oct(mode)}, "
            f"owner={owner}:{group})"
        )
        return "skip: dry-run" if existed else "ok"
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, uid, gid)
    except (KeyError, PermissionError):
        # owner/group not yet created, or we're not root (--prefix tests).
        # mkdir is the load-bearing part; perm bits come back on the real
        # root run.
        pass
    return f"skip: {path} already present" if existed else "ok"


def _ensure_config(path: Path, group: str, *, dry_run: bool) -> str:
    if path.exists():
        return f"skip: {path} already present"
    if dry_run:
        console.print(f"  [dim]would write:[/] {path}")
        return "ok"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_CONFIG_PLACEHOLDER)
    try:
        os.chmod(path, 0o640)
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, 0, gid)
    except (KeyError, PermissionError):
        pass
    return "ok"


def _copy_if_changed(
    src: Path, dst: Path, *, mode: int, force: bool, dry_run: bool
) -> str:
    if dst.exists() and not force and _sha256(src) == _sha256(dst):
        return f"skip: {dst} up to date"
    if dry_run:
        console.print(f"  [dim]would install:[/] {src} -> {dst} (mode={oct(mode)})")
        return "ok"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    try:
        os.chmod(dst, mode)
        os.chown(dst, 0, 0)
    except PermissionError:
        pass
    return "ok"


def _install_units(
    deploy: Path, systemd_dir: Path, *, force: bool, dry_run: bool
) -> str:
    sources = sorted(deploy.glob("decnet-*.service")) + [deploy / "decnet.target"]
    touched = 0
    for src in sources:
        result = _copy_if_changed(
            src, systemd_dir / src.name,
            mode=0o644, force=force, dry_run=dry_run,
        )
        if not result.startswith("skip:"):
            touched += 1
    total = len(sources)
    if touched == 0:
        return f"skip: {total} unit files up to date"
    return f"ok ({touched}/{total} installed)"


def _install_polkit(
    deploy: Path, rules_dir: Path, *, force: bool, dry_run: bool
) -> str:
    src = deploy / "polkit" / "50-decnet-workers.rules"
    if not src.is_file():
        raise RuntimeError(f"missing polkit rule at {src}")
    return _copy_if_changed(
        src, rules_dir / src.name,
        mode=0o644, force=force, dry_run=dry_run,
    )


def _install_tmpfiles(
    deploy: Path, tmpfiles_dir: Path, *, force: bool, dry_run: bool
) -> str:
    src = deploy / "tmpfiles.d" / "decnet.conf"
    if not src.is_file():
        raise RuntimeError(f"missing tmpfiles.d entry at {src}")
    result = _copy_if_changed(
        src, tmpfiles_dir / src.name,
        mode=0o644, force=force, dry_run=dry_run,
    )
    # Apply immediately so /run/decnet exists before daemon-reload.
    _run(["systemd-tmpfiles", "--create", str(tmpfiles_dir / src.name)], dry_run=dry_run)
    return result


def register(app: typer.Typer) -> None:
    @app.command(name="init")
    def init_cmd(
        dry_run: bool = typer.Option(
            False, "--dry-run",
            help="Print every action; make no changes.",
        ),
        no_start: bool = typer.Option(
            False, "--no-start",
            help="Install everything but don't `systemctl enable --now decnet.target`.",
        ),
        force: bool = typer.Option(
            False, "--force",
            help="Overwrite unit / polkit / tmpfiles entries even if identical.",
        ),
        user: str = typer.Option(
            "decnet", "--user",
            help="System user to own DECNET processes.",
        ),
        group: str = typer.Option(
            "decnet", "--group",
            help="Primary group of the DECNET user.",
        ),
        prefix: str = typer.Option(
            "", "--prefix", hidden=True,
            help="Filesystem prefix for tests (e.g. tmp_path). Empty = real root.",
        ),
    ) -> None:
        """One-shot bootstrap of a DECNET master host.

        Creates the `decnet` user/group, installs systemd units,
        polkit rules, tmpfiles.d entries, seeds directories and
        drops a placeholder config, then starts decnet.target.
        """
        _require_master_mode("init")

        # Root check — skip when --prefix is set (tests don't run as root).
        if not prefix and os.geteuid() != 0:
            console.print("[red]decnet init: must run as root (use sudo)[/]")
            raise typer.Exit(1)

        for tool in ("systemctl", "useradd", "groupadd", "systemd-tmpfiles"):
            if shutil.which(tool) is None and not dry_run:
                console.print(f"[red]decnet init: {tool!r} is required on PATH[/]")
                raise typer.Exit(1)

        try:
            deploy = _deploy_root()
        except RuntimeError as exc:
            console.print(f"[red]decnet init: {exc}[/]")
            raise typer.Exit(1) from exc

        pfx = Path(prefix) if prefix else Path("/")
        systemd_dir = pfx / "etc/systemd/system"
        polkit_dir = pfx / "etc/polkit-1/rules.d"
        tmpfiles_dir = pfx / "etc/tmpfiles.d"
        etc_decnet = pfx / "etc/decnet"
        dirs = [
            (pfx / "opt/decnet", 0o755, user, group),
            (pfx / "var/lib/decnet", 0o750, user, group),
            (pfx / "var/log/decnet", 0o750, user, group),
            (etc_decnet, 0o755, "root", group),
            (pfx / "run/decnet", 0o755, "root", group),
        ]

        console.print(
            f"[bold cyan]DECNET init[/] "
            f"(dry_run={dry_run}, no_start={no_start}, force={force})"
        )

        _step(
            f"ensure group {group!r}",
            lambda: _ensure_group(group, dry_run=dry_run),
        )
        _step(
            f"ensure user {user!r}",
            lambda: _ensure_user(user, group, dry_run=dry_run),
        )
        for path, mode, d_owner, d_group in dirs:
            _step(
                f"ensure dir {path}",
                lambda p=path, m=mode, o=d_owner, g=d_group:
                    _ensure_dir(p, mode=m, owner=o, group=g, dry_run=dry_run),
            )
        _step(
            f"write {etc_decnet / 'config.ini'}",
            lambda: _ensure_config(etc_decnet / "config.ini", group, dry_run=dry_run),
        )
        _step(
            "install systemd units",
            lambda: _install_units(
                deploy, systemd_dir, force=force, dry_run=dry_run,
            ),
        )
        _step(
            "install polkit rule",
            lambda: _install_polkit(
                deploy, polkit_dir, force=force, dry_run=dry_run,
            ),
        )
        _step(
            "install tmpfiles.d entry",
            lambda: _install_tmpfiles(
                deploy, tmpfiles_dir, force=force, dry_run=dry_run,
            ),
        )
        _step(
            "systemctl daemon-reload",
            lambda: (_run(["systemctl", "daemon-reload"], dry_run=dry_run), "ok")[1],
        )

        if no_start:
            console.print("[yellow]--no-start: skipping decnet.target start[/]")
            return

        try:
            _step(
                "systemctl enable --now decnet.target",
                lambda: (
                    _run(
                        ["systemctl", "enable", "--now", "decnet.target"],
                        dry_run=dry_run,
                    ),
                    "ok",
                )[1],
            )
        except subprocess.CalledProcessError as exc:
            console.print(
                f"[red]decnet.target failed to start (rc={exc.returncode}); "
                "inspect `systemctl status decnet.target` and individual "
                "`decnet-*.service` units.[/]"
            )
            raise typer.Exit(1) from exc

        console.print("[bold green]DECNET init complete.[/] "
                      "Check `decnet status` or the Workers panel.")
        sys.stdout.flush()
