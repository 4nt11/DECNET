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
from typing import Callable, List, Optional

import typer
from jinja2 import Environment, FileSystemLoader, StrictUndefined

import decnet as _decnet_pkg
from .gating import _require_master_mode
from .utils import console, log


_CONFIG_PLACEHOLDER = """\
# /etc/decnet/decnet.ini — DECNET host config.
#
# Every key is OPTIONAL. Absent keys fall through to env-var defaults
# defined in decnet/env.py. Real env vars always win over this file
# (precedence: env > INI > default), so systemd EnvironmentFile= and
# one-off `DECNET_FOO=bar decnet ...` invocations always take effect.
#
# Secrets (JWT, admin password, DB password) intentionally DO NOT
# live here. Put them in /opt/decnet/.env.local or the systemd
# EnvironmentFile= — never in a group-readable INI.

[decnet]
# mode = master                          # or "agent"

# [api]
# host = 127.0.0.1
# port = 8000

# [web]
# host = 127.0.0.1
# port = 8080
# admin-user = admin
# cors-origins = http://localhost:8080   # comma-separated

# [database]
# type = sqlite                          # or "mysql"
# url = mysql+asyncmy://user@host:3306/decnet   # if set, wins over host/port/name/user
# host = localhost
# port = 3306
# name = decnet
# user = decnet

# [bus]
# enabled = true
# type = unix                            # or "fake"
# socket = /run/decnet/bus.sock
# group = decnet

# [swarm]
# master-host = 10.0.0.1
# syslog-port = 6514
# swarmctl-port = 8770

# [logging]
# system-log = /var/log/decnet/decnet.system.log
# ingest-log = /var/log/decnet/decnet.log
# agent-log  = /var/log/decnet/agent.log

# [ingester]
# batch-size = 100
# batch-max-wait-ms = 250

# [tracing]
# enabled = false
# otel-endpoint = http://localhost:4317

# [agent]
# Managed by the enroll bundle — do NOT edit by hand on an agent host.
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


def _ensure_user(user: str, group: str, install_dir: str, *, dry_run: bool) -> str:
    try:
        pwd.getpwnam(user)
        return f"skip: user {user} already exists"
    except KeyError:
        _run(
            [
                "useradd", "--system",
                "--gid", group,
                "--home-dir", install_dir,
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


def _render_template(src: Path, context: dict[str, str]) -> str:
    """Render a Jinja2 .j2 template with the given context.

    StrictUndefined: a missing context variable is an error, not a
    silent empty-string substitution — that way a typo in the template
    fails loudly instead of shipping a broken systemd unit.
    """
    env = Environment(
        loader=FileSystemLoader(str(src.parent)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,  # nosec B701 — rendering systemd INI, not HTML
    )
    template = env.get_template(src.name)
    return template.render(**context)


def _write_rendered_if_changed(
    src: Path, dst: Path, rendered: str, *, mode: int, force: bool, dry_run: bool
) -> str:
    """Write *rendered* content to *dst* only if it differs from what's there.

    SHA compares rendered-output ↔ on-disk bytes (NOT source-template ↔
    on-disk) so operators who customise their install_dir get idempotent
    re-runs instead of every ``decnet init`` rewriting files.
    """
    rendered_bytes = rendered.encode("utf-8")
    if dst.exists() and not force:
        if hashlib.sha256(dst.read_bytes()).hexdigest() == hashlib.sha256(rendered_bytes).hexdigest():
            return f"skip: {dst} up to date"
    if dry_run:
        console.print(f"  [dim]would render:[/] {src} -> {dst} (mode={oct(mode)})")
        return "ok"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(rendered_bytes)
    try:
        os.chmod(dst, mode)
        os.chown(dst, 0, 0)
    except PermissionError:
        pass
    return "ok"


def _resolve_venv_dir(install_dir: str, explicit: str | None) -> str:
    """Pick the virtualenv systemd units should ExecStart out of.

    Priority:
      1. ``--venv-dir`` flag (explicit; absolute path required).
      2. ``VIRTUAL_ENV`` env var, but only when it lives under
         ``install_dir`` (refuse to bake /home/user/.venv into a system
         service — that directory is user-owned and may vanish).
      3. ``{install_dir}/venv``  — what ``enroll_bootstrap.sh`` creates
         on fresh agents; the production default.
      4. First hit from a short list of dev-box conventions under
         ``install_dir``:  ``.venv``, ``.311``, ``.312``, ``.313``.

    Raises RuntimeError with an operator-friendly message if none of
    those resolve to a directory containing ``bin/decnet``. Failing loud
    at init time beats systemd spamming journalctl with
    'Failed at step EXEC spawning .../venv/bin/decnet: No such file or
    directory' on every auto-restart.
    """
    install_path = Path(install_dir)

    candidates: list[Path] = []
    if explicit:
        if not explicit.startswith("/"):
            raise RuntimeError(
                f"--venv-dir must be an absolute path, got {explicit!r}"
            )
        candidates.append(Path(explicit))
    else:
        virtual_env = os.environ.get("VIRTUAL_ENV")
        if virtual_env:
            ve_path = Path(virtual_env)
            try:
                ve_path.relative_to(install_path)
                candidates.append(ve_path)
            except ValueError:
                # VIRTUAL_ENV lives outside install_dir — don't bake a
                # user-home venv into a root-owned systemd unit.
                pass
        candidates.append(install_path / "venv")
        for name in (".venv", ".311", ".312", ".313"):
            candidates.append(install_path / name)

    for cand in candidates:
        if (cand / "bin" / "decnet").is_file():
            return str(cand)

    searched = ", ".join(str(c) for c in candidates)
    raise RuntimeError(
        "Could not find a DECNET venv. Create one first (e.g. "
        f"`python -m venv {install_path}/venv && "
        f"{install_path}/venv/bin/pip install -e {install_path}[dev]`) "
        "or pass --venv-dir. Searched: " + searched
    )


def _install_units(
    deploy: Path,
    systemd_dir: Path,
    *,
    install_dir: str,
    venv_dir: str,
    user: str,
    group: str,
    force: bool,
    dry_run: bool,
) -> str:
    """Render decnet-*.service.j2 → systemd_dir/decnet-*.service, and copy
    the static decnet.target (no templating needed — it has no install
    path references)."""
    context = {
        "install_dir": install_dir,
        "venv_dir": venv_dir,
        "user": user,
        "group": group,
    }
    templates = sorted(deploy.glob("decnet-*.service.j2"))
    static = [deploy / "decnet.target"]

    touched = 0
    for src in templates:
        rendered = _render_template(src, context)
        # decnet-api.service.j2 → decnet-api.service
        dst_name = src.name[: -len(".j2")]
        result = _write_rendered_if_changed(
            src, systemd_dir / dst_name, rendered,
            mode=0o644, force=force, dry_run=dry_run,
        )
        if not result.startswith("skip:"):
            touched += 1
    for src in static:
        result = _copy_if_changed(
            src, systemd_dir / src.name,
            mode=0o644, force=force, dry_run=dry_run,
        )
        if not result.startswith("skip:"):
            touched += 1
    total = len(templates) + len(static)
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


def _run_allow_fail(argv: List[str], *, dry_run: bool) -> str:
    """Like ``_run`` but tolerates non-zero exits (stop/disable on an
    already-absent unit is fine during deinit)."""
    if dry_run:
        console.print(f"  [dim]would run (allow fail):[/] {' '.join(argv)}")
        return "ok"
    log.info("init: exec (allow fail) %s", argv)
    result = subprocess.run(argv, check=False)  # nosec B603
    if result.returncode != 0:
        return f"skip: rc={result.returncode} (already absent)"
    return "ok"


def _remove_file(path: Path, *, dry_run: bool) -> str:
    if not path.exists() and not path.is_symlink():
        return f"skip: {path} already absent"
    if dry_run:
        console.print(f"  [dim]would remove:[/] {path}")
        return "ok"
    path.unlink()
    return "ok"


def _uninstall_units(systemd_dir: Path, *, dry_run: bool) -> str:
    removed = 0
    present = sorted(systemd_dir.glob("decnet-*.service"))
    target = systemd_dir / "decnet.target"
    if target.exists():
        present.append(target)
    for path in present:
        if dry_run:
            console.print(f"  [dim]would remove:[/] {path}")
            removed += 1
            continue
        path.unlink()
        removed += 1
    if removed == 0:
        return "skip: no decnet unit files present"
    return f"ok ({removed} removed)"


def _remove_user(user: str, *, dry_run: bool) -> str:
    try:
        pwd.getpwnam(user)
    except KeyError:
        return f"skip: user {user} already absent"
    # userdel returns non-zero if the user still owns running
    # processes; that's the operator's problem to sort out, not ours.
    return _run_allow_fail(["userdel", user], dry_run=dry_run)


def _remove_group(group: str, *, dry_run: bool) -> str:
    try:
        grp.getgrnam(group)
    except KeyError:
        return f"skip: group {group} already absent"
    return _run_allow_fail(["groupdel", group], dry_run=dry_run)


def _remove_dir_if_present(
    path: Path, *, dry_run: bool, recursive: bool = False
) -> str:
    if not path.exists():
        return f"skip: {path} already absent"
    if dry_run:
        verb = "would rm -rf" if recursive else "would rmdir"
        console.print(f"  [dim]{verb}:[/] {path}")
        return "ok"
    if recursive:
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            path.rmdir()
        except OSError as exc:
            return f"skip: {path} not empty ({exc.strerror})"
    return "ok"


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
        deinit: bool = typer.Option(
            False, "--deinit",
            help="Undo a previous init: stop + disable decnet.target, remove "
                 "unit files, polkit rule, tmpfiles.d entry, /etc/decnet. "
                 "Preserves /var/lib/decnet, /var/log/decnet, and the "
                 "service user/group — pass --purge to remove those too.",
        ),
        purge: bool = typer.Option(
            False, "--purge",
            help="With --deinit, also wipe /var/lib/decnet, "
                 "/var/log/decnet, AND the service user/group. "
                 "Destructive — operator data is gone, and if --user "
                 "points at your own login account, that account goes "
                 "with it. Only use when the user/group was created by "
                 "`decnet init` in the first place.",
        ),
        user: str = typer.Option(
            "decnet", "--user",
            help="System user to own DECNET processes.",
        ),
        group: str = typer.Option(
            "decnet", "--group",
            help="Primary group of the DECNET user.",
        ),
        install_dir: str = typer.Option(
            "/opt/decnet", "--install-dir",
            help="Absolute path where DECNET is installed. Default "
                 "/opt/decnet; distros that reserve /opt can point this "
                 "at /srv/decnet, /usr/local/decnet, etc. Gets rendered "
                 "into every systemd unit via Jinja2 and used as the "
                 "decnet user's home directory.",
        ),
        venv_dir: Optional[str] = typer.Option(
            None, "--venv-dir",
            help="Absolute path to the Python venv systemd should "
                 "ExecStart from. If omitted, auto-detected in order: "
                 "$VIRTUAL_ENV (if under --install-dir), "
                 "{install-dir}/venv, then {install-dir}/{.venv,.311,"
                 ".312,.313}. Init aborts if none exists.",
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

        if purge and not deinit:
            console.print("[red]--purge only applies with --deinit[/]")
            raise typer.Exit(1)

        # Root check — skip when --prefix is set (tests don't run as root).
        if not prefix and os.geteuid() != 0:
            verb = "deinit" if deinit else "init"
            console.print(f"[red]decnet {verb}: must run as root (use sudo)[/]")
            raise typer.Exit(1)

        if not install_dir.startswith("/"):
            console.print(
                f"[red]decnet init: --install-dir must be absolute, got {install_dir!r}[/]"
            )
            raise typer.Exit(1)
        # Strip leading slash so pfx-joining works under --prefix test mode
        # (Path("/").  / "/opt/decnet" == Path("/opt/decnet"), dropping pfx).
        _install_rel = install_dir.lstrip("/")

        required_tools = ("systemctl",) if deinit else (
            "systemctl", "useradd", "groupadd", "systemd-tmpfiles",
        )
        if deinit:
            required_tools = required_tools + ("userdel", "groupdel")
        for tool in required_tools:
            if shutil.which(tool) is None and not dry_run:
                verb = "deinit" if deinit else "init"
                console.print(f"[red]decnet {verb}: {tool!r} is required on PATH[/]")
                raise typer.Exit(1)

        pfx = Path(prefix) if prefix else Path("/")
        systemd_dir = pfx / "etc/systemd/system"
        polkit_dir = pfx / "etc/polkit-1/rules.d"
        tmpfiles_dir = pfx / "etc/tmpfiles.d"
        etc_decnet = pfx / "etc/decnet"

        if deinit:
            console.print(
                f"[bold cyan]DECNET deinit[/] "
                f"(dry_run={dry_run}, purge={purge})"
            )
            _step(
                "systemctl stop + disable decnet.target",
                lambda: _run_allow_fail(
                    ["systemctl", "disable", "--now", "decnet.target"],
                    dry_run=dry_run,
                ),
            )
            _step(
                "remove systemd unit files",
                lambda: _uninstall_units(systemd_dir, dry_run=dry_run),
            )
            _step(
                "remove polkit rule",
                lambda: _remove_file(
                    polkit_dir / "50-decnet-workers.rules",
                    dry_run=dry_run,
                ),
            )
            _step(
                "remove tmpfiles.d entry",
                lambda: _remove_file(
                    tmpfiles_dir / "decnet.conf",
                    dry_run=dry_run,
                ),
            )
            _step(
                "systemctl daemon-reload",
                lambda: (_run(["systemctl", "daemon-reload"], dry_run=dry_run), "ok")[1],
            )
            _step(
                f"remove {etc_decnet / 'decnet.ini'}",
                lambda: _remove_file(etc_decnet / "decnet.ini", dry_run=dry_run),
            )
            # Legacy name from pre-domain-sections placeholder era.
            # Harmless if absent (the _remove_file step logs skip).
            _step(
                f"remove legacy {etc_decnet / 'config.ini'}",
                lambda: _remove_file(etc_decnet / "config.ini", dry_run=dry_run),
            )
            _step(
                f"remove {etc_decnet}",
                lambda: _remove_dir_if_present(etc_decnet, dry_run=dry_run),
            )
            _step(
                f"remove {pfx / 'run/decnet'}",
                lambda: _remove_dir_if_present(
                    pfx / "run/decnet", dry_run=dry_run,
                ),
            )
            _step(
                f"remove {pfx / _install_rel}",
                lambda: _remove_dir_if_present(
                    pfx / _install_rel, dry_run=dry_run,
                ),
            )
            if purge:
                _step(
                    f"purge {pfx / 'var/lib/decnet'}",
                    lambda: _remove_dir_if_present(
                        pfx / "var/lib/decnet",
                        dry_run=dry_run, recursive=True,
                    ),
                )
                _step(
                    f"purge {pfx / 'var/log/decnet'}",
                    lambda: _remove_dir_if_present(
                        pfx / "var/log/decnet",
                        dry_run=dry_run, recursive=True,
                    ),
                )
            else:
                console.print(
                    f"[dim]preserved {pfx / 'var/lib/decnet'} and "
                    f"{pfx / 'var/log/decnet'} (operator data); "
                    "re-run with --purge to remove.[/]"
                )
            # User / group removal is also gated on --purge. In dev the
            # operator may have passed their own login user via
            # `--user $USER` to avoid ownership churn; an unconditional
            # `userdel anti` during deinit would nuke their account.
            if purge:
                _step(
                    f"remove user {user!r}",
                    lambda: _remove_user(user, dry_run=dry_run),
                )
                _step(
                    f"remove group {group!r}",
                    lambda: _remove_group(group, dry_run=dry_run),
                )
            else:
                console.print(
                    f"[dim]preserved user {user!r} and group {group!r}; "
                    "re-run with --purge to remove (only do this if "
                    "they were created by `decnet init`).[/]"
                )
            console.print("[bold green]DECNET deinit complete.[/]")
            return

        try:
            deploy = _deploy_root()
        except RuntimeError as exc:
            console.print(f"[red]decnet init: {exc}[/]")
            raise typer.Exit(1) from exc

        # Resolve venv BEFORE any file writes — fails loud if the
        # operator hasn't created one yet, instead of shipping broken
        # systemd units that journalctl spams forever. Skipped under
        # --prefix (test mode) because the test harness doesn't build a
        # real venv and the rendered string is asserted on directly.
        if prefix:
            resolved_venv = venv_dir or f"{install_dir}/venv"
        else:
            try:
                resolved_venv = _resolve_venv_dir(install_dir, venv_dir)
            except RuntimeError as exc:
                console.print(f"[red]decnet init: {exc}[/]")
                raise typer.Exit(1) from exc
            console.print(f"[dim]using venv: {resolved_venv}[/]")

        dirs = [
            (pfx / _install_rel, 0o755, user, group),
            (pfx / "var/lib/decnet", 0o750, user, group),
            (pfx / "var/lib/decnet/geoip", 0o755, user, group),
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
            lambda: _ensure_user(user, group, install_dir, dry_run=dry_run),
        )
        for path, mode, d_owner, d_group in dirs:
            _step(
                f"ensure dir {path}",
                lambda p=path, m=mode, o=d_owner, g=d_group:
                    _ensure_dir(p, mode=m, owner=o, group=g, dry_run=dry_run),
            )
        _step(
            f"write {etc_decnet / 'decnet.ini'}",
            lambda: _ensure_config(etc_decnet / "decnet.ini", group, dry_run=dry_run),
        )
        _step(
            "install systemd units",
            lambda: _install_units(
                deploy, systemd_dir,
                install_dir=install_dir, venv_dir=resolved_venv,
                user=user, group=group,
                force=force, dry_run=dry_run,
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
