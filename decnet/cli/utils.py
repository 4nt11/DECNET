# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared CLI helpers: console, logger, process management, swarm HTTP client.

Submodules reference these as ``from . import utils`` then ``utils.foo(...)``
so tests can patch ``decnet.cli.utils.<name>`` and have every caller see it.
"""

from __future__ import annotations

import os
import signal
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, Callable, Optional

import typer
from rich.console import Console

from decnet.logging import get_logger
from decnet.env import DECNET_API_HOST, DECNET_API_PORT, DECNET_INGEST_LOG_FILE

log = get_logger("cli")
console = Console()


def _daemonize() -> None:
    """Fork the current process into a background daemon (Unix double-fork)."""
    if os.fork() > 0:
        raise SystemExit(0)
    os.setsid()
    if os.fork() > 0:
        raise SystemExit(0)
    sys.stdout = open(os.devnull, "w")  # noqa: SIM115
    sys.stderr = open(os.devnull, "w")  # noqa: SIM115
    sys.stdin = open(os.devnull, "r")  # noqa: SIM115


def _pid_dir() -> Path:
    """Return the writable PID directory.

    /opt/decnet when it exists and is writable (production), else
    ~/.decnet (dev). The directory is created if needed."""
    candidates = [Path("/opt/decnet"), Path.home() / ".decnet"]
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            if os.access(path, os.W_OK):
                return path
        except (PermissionError, OSError):
            continue
    return Path("/tmp")  # nosec B108


def _spawn_detached(argv: list[str], pid_file: Path) -> int:
    """Spawn a DECNET subcommand as a fully-independent sibling process.

    The parent does NOT wait() on this child. start_new_session=True puts
    the child in its own session so SIGHUP on parent exit doesn't kill it;
    stdin/stdout/stderr go to /dev/null so the launching shell can close
    without EIO on the child. close_fds=True prevents inherited sockets
    from pinning ports we're trying to rebind.

    This is deliberately NOT a supervisor — we fire-and-forget. If the
    child dies, the operator restarts it manually via its own subcommand.
    """
    if pid_file.exists():
        try:
            existing = int(pid_file.read_text().strip())
            os.kill(existing, 0)
            return existing
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            pass  # stale pid_file — fall through and spawn

    with open(os.devnull, "rb") as dn_in, open(os.devnull, "ab") as dn_out:
        proc = subprocess.Popen(  # nosec B603
            argv,
            stdin=dn_in, stdout=dn_out, stderr=dn_out,
            start_new_session=True, close_fds=True,
        )
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f"{proc.pid}\n")
    return proc.pid


def _is_running(match_fn) -> int | None:
    """Return PID of a running DECNET process matching ``match_fn(cmdline)``, or None."""
    import psutil

    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = proc.info["cmdline"]
            if cmd and match_fn(cmd):
                return proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def _service_registry(log_file: str) -> list[tuple[str, Callable[..., Any], list[str]]]:
    """Return the microservice registry for health-check and relaunch.

    On agents these run as systemd units invoking /usr/local/bin/decnet,
    which doesn't include "decnet.cli" in its cmdline. On master dev boxes
    they're launched via `python -m decnet.cli`. Match either form — cmd
    is a list of argv tokens, so substring-check the joined string.
    """
    _py = sys.executable

    def _matches(sub: str, extras: tuple[str, ...] = ()):
        def _check(cmd) -> bool:
            joined = " ".join(cmd) if not isinstance(cmd, str) else cmd
            if "decnet" not in joined:
                return False
            if sub not in joined:
                return False
            return all(e in joined for e in extras)
        return _check

    return [
        ("Collector", _matches("collect"),
         [_py, "-m", "decnet.cli", "collect", "--daemon", "--log-file", log_file]),
        ("Mutator", _matches("mutate", ("--watch",)),
         [_py, "-m", "decnet.cli", "mutate", "--daemon", "--watch"]),
        ("Prober", _matches("probe"),
         [_py, "-m", "decnet.cli", "probe", "--daemon", "--log-file", log_file]),
        ("Profiler", _matches("profiler"),
         [_py, "-m", "decnet.cli", "profiler", "--daemon"]),
        ("Sniffer", _matches("sniffer"),
         [_py, "-m", "decnet.cli", "sniffer", "--daemon", "--log-file", log_file]),
        ("API",
         lambda cmd: "uvicorn" in cmd and "decnet.web.api:app" in cmd,
         [_py, "-m", "uvicorn", "decnet.web.api:app",
          "--host", DECNET_API_HOST, "--port", str(DECNET_API_PORT)]),
    ]


def _systemd_units(pattern: str = "decnet-*.service") -> list[dict] | None:
    """Return state of every systemd unit matching *pattern*, or ``None``
    when systemctl is unavailable (non-systemd host, container lab,
    PATH-stripped env, user-manager unreachable).

    Output shape mirrors ``systemctl list-units --output=json``: each
    dict has ``unit``, ``load``, ``active``, ``sub``, ``description``.
    Empty list = systemd works but no matching units are loaded (fresh
    host that never ran ``decnet init``).
    """
    import json  # local import — avoids paying it on every CLI startup
    import shutil

    if not shutil.which("systemctl"):
        return None
    try:
        proc = subprocess.run(  # nosec B603 B607 — fixed argv, no shell
            [
                "systemctl", "list-units",
                "--type=service", "--all",
                "--no-legend", "--no-pager",
                "--output=json",
                pattern,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, list) else None


def _kill_all_services() -> None:
    """Find and kill all running DECNET microservice processes."""
    registry = _service_registry(str(DECNET_INGEST_LOG_FILE))
    killed = 0
    for name, match_fn, _launch_args in registry:
        pid = _is_running(match_fn)
        if pid is not None:
            console.print(f"[yellow]Stopping {name} (PID {pid})...[/]")
            os.kill(pid, signal.SIGTERM)
            killed += 1

    if killed:
        console.print(f"[green]{killed} background process(es) stopped.[/]")
    else:
        console.print("[dim]No DECNET services were running.[/]")


_DEFAULT_SWARMCTL_URL = "http://127.0.0.1:8770"


def _swarmctl_base_url(url: Optional[str]) -> str:
    return url or os.environ.get("DECNET_SWARMCTL_URL") or _DEFAULT_SWARMCTL_URL


def _swarmctl_auth_headers() -> dict[str, str]:
    """Bearer header for swarm-controller calls.

    The controller now requires an admin-role JWT on every control-plane route
    (defense-in-depth on top of the loopback/mTLS transport gate). Operators
    export ``DECNET_API_TOKEN`` (the access_token from POST /api/v1/auth/login)
    so the CLI can authenticate. Absent the var we send no header and the
    controller answers 401 — fail closed, with a clear hint surfaced by
    :func:`_http_request`.
    """
    token = os.environ.get("DECNET_API_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _http_request(method: str, url: str, *, json_body: Optional[dict] = None, timeout: float = 30.0):
    """Tiny sync wrapper around httpx; avoids leaking async into the CLI."""
    import httpx
    try:
        resp = httpx.request(
            method, url, json=json_body, timeout=timeout, headers=_swarmctl_auth_headers()
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]Could not reach swarm controller at {url}: {exc}[/]")
        console.print("[dim]Is `decnet swarmctl` running?[/]")
        raise typer.Exit(2)
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:  # nosec B110
            detail = resp.text
        console.print(f"[red]{method} {url} failed: {resp.status_code} — {detail}[/]")
        if resp.status_code in (401, 403):
            console.print(
                "[dim]The swarm controller requires an admin JWT. Export "
                "DECNET_API_TOKEN with an access_token from "
                "POST /api/v1/auth/login (admin user). "
                "If you receive 403 'Password change required', change the "
                "password first (POST /api/v1/auth/change-password), then "
                "log in again to obtain a fresh token.[/]"
            )
        raise typer.Exit(1)
    return resp
