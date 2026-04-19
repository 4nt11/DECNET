"""
DECNET CLI — entry point for all commands.

Usage:
  decnet deploy --mode unihost --deckies 5 --randomize-services
  decnet status
  decnet teardown [--all | --id decky-01]
  decnet services
"""

import signal
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from decnet.logging import get_logger
from decnet.env import (
    DECNET_API_HOST,
    DECNET_API_PORT,
    DECNET_INGEST_LOG_FILE,
    DECNET_WEB_HOST,
    DECNET_WEB_PORT,
)
from decnet.archetypes import Archetype, all_archetypes, get_archetype
from decnet.config import (
    DecnetConfig,
)
from decnet.distros import all_distros, get_distro
from decnet.fleet import all_service_names, build_deckies, build_deckies_from_ini
from decnet.ini_loader import load_ini
from decnet.network import detect_interface, detect_subnet, allocate_ips, get_host_ip
from decnet.services.registry import all_services

log = get_logger("cli")


def _daemonize() -> None:
    """Fork the current process into a background daemon (Unix double-fork)."""
    import os
    import sys

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
    import os
    candidates = [Path("/opt/decnet"), Path.home() / ".decnet"]
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            if os.access(path, os.W_OK):
                return path
        except (PermissionError, OSError):
            continue
    # Last-resort fallback so we never raise from a helper.
    return Path("/tmp")  # nosec B108


def _spawn_detached(argv: list[str], pid_file: Path) -> int:
    """Spawn a DECNET subcommand as a fully-independent sibling process.

    The parent does NOT wait() on this child. start_new_session=True puts
    the child in its own session so SIGHUP on parent exit doesn't kill it;
    stdin/stdout/stderr go to /dev/null so the launching shell can close
    without EIO on the child. close_fds=True prevents inherited sockets
    from pinning ports we're trying to rebind.

    This is deliberately NOT a supervisor — we fire-and-forget. If the
    child dies, the operator restarts it manually via its own subcommand
    (e.g. `decnet forwarder --daemon …`). Detached means detached.
    """
    import os
    import subprocess  # nosec B404

    # If the pid_file points at a live process, don't spawn a duplicate —
    # agent/swarmctl auto-spawn is called on every startup, and the first
    # run's sibling is still alive across restarts.
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


app = typer.Typer(
    name="decnet",
    help="Deploy a deception network of honeypot deckies on your LAN.",
    no_args_is_help=True,
)
console = Console()


def _kill_all_services() -> None:
    """Find and kill all running DECNET microservice processes."""
    import os

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


@app.command()
def api(
    port: int = typer.Option(DECNET_API_PORT, "--port", help="Port for the backend API"),
    host: str = typer.Option(DECNET_API_HOST, "--host", help="Host IP for the backend API"),
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Path to the DECNET log file to monitor"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    workers: int = typer.Option(1, "--workers", "-w", min=1, help="Number of uvicorn worker processes"),
) -> None:
    """Run the DECNET API and Web Dashboard in standalone mode."""
    import subprocess  # nosec B404
    import sys
    import os
    import signal

    _require_master_mode("api")
    if daemon:
        log.info("API daemonizing host=%s port=%d workers=%d", host, port, workers)
        _daemonize()

    log.info("API command invoked host=%s port=%d workers=%d", host, port, workers)
    console.print(f"[green]Starting DECNET API on {host}:{port} (workers={workers})...[/]")
    _env: dict[str, str] = os.environ.copy()
    _env["DECNET_INGEST_LOG_FILE"] = str(log_file)
    _cmd = [sys.executable, "-m", "uvicorn", "decnet.web.api:app",
            "--host", host, "--port", str(port), "--workers", str(workers)]
    # Put uvicorn (and its worker children) in their own process group so we
    # can signal the whole tree on Ctrl+C. Without this, only the supervisor
    # receives SIGINT from the terminal and worker children may survive and
    # be respawned — the "forkbomb" ANTI hit during testing.
    try:
        proc = subprocess.Popen(_cmd, env=_env, start_new_session=True)  # nosec B603 B404
        try:
            proc.wait()
        except KeyboardInterrupt:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            except ProcessLookupError:
                pass
    except (FileNotFoundError, subprocess.SubprocessError):
        console.print("[red]Failed to start API. Ensure 'uvicorn' is installed in the current environment.[/]")


@app.command()
def swarmctl(
    port: int = typer.Option(8770, "--port", help="Port for the swarm controller"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the swarm controller"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    no_listener: bool = typer.Option(False, "--no-listener", help="Do not auto-spawn the syslog-TLS listener alongside swarmctl"),
) -> None:
    """Run the DECNET SWARM controller (master-side, separate process from `decnet api`).

    By default, `decnet swarmctl` auto-spawns `decnet listener` as a fully-
    detached sibling process so the master starts accepting forwarder
    connections on 6514 without a second manual invocation. The listener
    survives swarmctl restarts and crashes — if it dies on its own,
    restart it manually with `decnet listener --daemon …`. Pass
    --no-listener to skip.
    """
    import subprocess  # nosec B404
    import sys
    import os
    import signal

    _require_master_mode("swarmctl")
    if daemon:
        log.info("swarmctl daemonizing host=%s port=%d", host, port)
        _daemonize()

    if not no_listener:
        listener_host = os.environ.get("DECNET_LISTENER_HOST", "0.0.0.0")  # nosec B104
        listener_port = int(os.environ.get("DECNET_SWARM_SYSLOG_PORT", "6514"))
        lst_argv = [
            sys.executable, "-m", "decnet", "listener",
            "--host", listener_host,
            "--port", str(listener_port),
            "--daemon",
        ]
        try:
            pid = _spawn_detached(lst_argv, _pid_dir() / "listener.pid")
            log.info("swarmctl auto-spawned listener pid=%d bind=%s:%d",
                     pid, listener_host, listener_port)
            console.print(f"[dim]Auto-spawned listener (pid {pid}) on {listener_host}:{listener_port}.[/]")
        except Exception as e:  # noqa: BLE001
            log.warning("swarmctl could not auto-spawn listener: %s", e)
            console.print(f"[yellow]listener auto-spawn skipped: {e}[/]")

    log.info("swarmctl command invoked host=%s port=%d", host, port)
    console.print(f"[green]Starting DECNET SWARM controller on {host}:{port}...[/]")
    _cmd = [sys.executable, "-m", "uvicorn", "decnet.web.swarm_api:app",
            "--host", host, "--port", str(port)]
    try:
        proc = subprocess.Popen(_cmd, start_new_session=True)  # nosec B603 B404
        try:
            proc.wait()
        except KeyboardInterrupt:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            except ProcessLookupError:
                pass
    except (FileNotFoundError, subprocess.SubprocessError):
        console.print("[red]Failed to start swarmctl. Ensure 'uvicorn' is installed in the current environment.[/]")


@app.command()
def agent(
    port: int = typer.Option(8765, "--port", help="Port for the worker agent"),
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address for the worker agent"),  # nosec B104
    agent_dir: Optional[str] = typer.Option(None, "--agent-dir", help="Worker cert bundle dir (default: ~/.decnet/agent, expanded under the running user's HOME — set this when running as sudo/root)"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    no_forwarder: bool = typer.Option(False, "--no-forwarder", help="Do not auto-spawn the log forwarder alongside the agent"),
) -> None:
    """Run the DECNET SWARM worker agent (requires a cert bundle in ~/.decnet/agent/).

    By default, `decnet agent` auto-spawns `decnet forwarder` as a fully-
    detached sibling process so worker logs start flowing to the master
    without a second manual invocation. The forwarder survives agent
    restarts and crashes — if it dies on its own, restart it manually
    with `decnet forwarder --daemon …`. Pass --no-forwarder to skip.
    """
    import os
    import pathlib as _pathlib
    import sys as _sys
    from decnet.agent import server as _agent_server
    from decnet.env import DECNET_SWARM_MASTER_HOST, DECNET_INGEST_LOG_FILE
    from decnet.swarm import pki as _pki

    resolved_dir = _pathlib.Path(agent_dir) if agent_dir else _pki.DEFAULT_AGENT_DIR

    if daemon:
        log.info("agent daemonizing host=%s port=%d", host, port)
        _daemonize()

    # Auto-spawn the forwarder as a detached sibling BEFORE blocking on the
    # agent server. Requires DECNET_SWARM_MASTER_HOST — if unset, the
    # auto-spawn is silently skipped (single-host dev, or operator plans to
    # start the forwarder separately).
    if not no_forwarder and DECNET_SWARM_MASTER_HOST:
        fw_argv = [
            _sys.executable, "-m", "decnet", "forwarder",
            "--master-host", DECNET_SWARM_MASTER_HOST,
            "--master-port", str(int(os.environ.get("DECNET_SWARM_SYSLOG_PORT", "6514"))),
            "--agent-dir", str(resolved_dir),
            "--log-file", str(DECNET_INGEST_LOG_FILE),
            "--daemon",
        ]
        try:
            pid = _spawn_detached(fw_argv, _pid_dir() / "forwarder.pid")
            log.info("agent auto-spawned forwarder pid=%d master=%s", pid, DECNET_SWARM_MASTER_HOST)
            console.print(f"[dim]Auto-spawned forwarder (pid {pid}) → {DECNET_SWARM_MASTER_HOST}.[/]")
        except Exception as e:  # noqa: BLE001
            log.warning("agent could not auto-spawn forwarder: %s", e)
            console.print(f"[yellow]forwarder auto-spawn skipped: {e}[/]")
    elif not no_forwarder:
        log.info("agent skipping forwarder auto-spawn (DECNET_SWARM_MASTER_HOST unset)")

    log.info("agent command invoked host=%s port=%d dir=%s", host, port, resolved_dir)
    console.print(f"[green]Starting DECNET worker agent on {host}:{port} (mTLS)...[/]")
    rc = _agent_server.run(host, port, agent_dir=resolved_dir)
    if rc != 0:
        raise typer.Exit(rc)


@app.command()
def updater(
    port: int = typer.Option(8766, "--port", help="Port for the self-updater daemon"),
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address for the updater"),  # nosec B104
    updater_dir: Optional[str] = typer.Option(None, "--updater-dir", help="Updater cert bundle dir (default: ~/.decnet/updater)"),
    install_dir: Optional[str] = typer.Option(None, "--install-dir", help="Release install root (default: /opt/decnet)"),
    agent_dir: Optional[str] = typer.Option(None, "--agent-dir", help="Worker agent cert bundle (for local /health probes; default: ~/.decnet/agent)"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Run the DECNET self-updater (requires a bundle in ~/.decnet/updater/)."""
    import pathlib as _pathlib
    from decnet.swarm import pki as _pki
    from decnet.updater import server as _upd_server

    resolved_updater = _pathlib.Path(updater_dir) if updater_dir else _upd_server.DEFAULT_UPDATER_DIR
    resolved_install = _pathlib.Path(install_dir) if install_dir else _pathlib.Path("/opt/decnet")
    resolved_agent = _pathlib.Path(agent_dir) if agent_dir else _pki.DEFAULT_AGENT_DIR

    if daemon:
        log.info("updater daemonizing host=%s port=%d", host, port)
        _daemonize()

    log.info(
        "updater command invoked host=%s port=%d updater_dir=%s install_dir=%s",
        host, port, resolved_updater, resolved_install,
    )
    console.print(f"[green]Starting DECNET self-updater on {host}:{port} (mTLS)...[/]")
    rc = _upd_server.run(
        host, port,
        updater_dir=resolved_updater,
        install_dir=resolved_install,
        agent_dir=resolved_agent,
    )
    if rc != 0:
        raise typer.Exit(rc)


@app.command()
def listener(
    bind_host: str = typer.Option("0.0.0.0", "--host", help="Bind address for the master syslog-TLS listener"),  # nosec B104
    bind_port: int = typer.Option(6514, "--port", help="Listener TCP port (RFC 5425 default 6514)"),
    log_path: Optional[str] = typer.Option(None, "--log-path", help="RFC 5424 forensic sink (default: ./master.log)"),
    json_path: Optional[str] = typer.Option(None, "--json-path", help="Parsed-JSON ingest sink (default: ./master.json)"),
    ca_dir: Optional[str] = typer.Option(None, "--ca-dir", help="DECNET CA dir (default: ~/.decnet/ca)"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Run the master-side syslog-over-TLS listener (RFC 5425, mTLS)."""
    import asyncio
    import pathlib
    from decnet.swarm import pki
    from decnet.swarm.log_listener import ListenerConfig, run_listener

    resolved_ca_dir = pathlib.Path(ca_dir) if ca_dir else pki.DEFAULT_CA_DIR
    resolved_log = pathlib.Path(log_path) if log_path else pathlib.Path("master.log")
    resolved_json = pathlib.Path(json_path) if json_path else pathlib.Path("master.json")

    cfg = ListenerConfig(
        log_path=resolved_log, json_path=resolved_json,
        bind_host=bind_host, bind_port=bind_port, ca_dir=resolved_ca_dir,
    )

    if daemon:
        log.info("listener daemonizing host=%s port=%d", bind_host, bind_port)
        _daemonize()

    log.info("listener command invoked host=%s port=%d", bind_host, bind_port)
    console.print(f"[green]Starting DECNET log listener on {bind_host}:{bind_port} (mTLS)...[/]")

    async def _main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass
        await run_listener(cfg, stop_event=stop)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


@app.command()
def forwarder(
    master_host: Optional[str] = typer.Option(None, "--master-host", help="Master listener hostname/IP (default: $DECNET_SWARM_MASTER_HOST)"),
    master_port: int = typer.Option(6514, "--master-port", help="Master listener TCP port (RFC 5425 default 6514)"),
    log_file: Optional[str] = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Local RFC 5424 file to tail and forward"),
    agent_dir: Optional[str] = typer.Option(None, "--agent-dir", help="Worker cert bundle dir (default: ~/.decnet/agent)"),
    state_db: Optional[str] = typer.Option(None, "--state-db", help="Forwarder offset SQLite path (default: <agent_dir>/forwarder.db)"),
    poll_interval: float = typer.Option(0.5, "--poll-interval", help="Seconds between log file stat checks"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Run the worker-side syslog-over-TLS forwarder (RFC 5425, mTLS to master:6514)."""
    import asyncio
    import pathlib
    from decnet.env import DECNET_SWARM_MASTER_HOST
    from decnet.swarm import pki
    from decnet.swarm.log_forwarder import ForwarderConfig, run_forwarder

    resolved_host = master_host or DECNET_SWARM_MASTER_HOST
    if not resolved_host:
        console.print("[red]--master-host is required (or set DECNET_SWARM_MASTER_HOST).[/]")
        raise typer.Exit(2)

    resolved_agent_dir = pathlib.Path(agent_dir) if agent_dir else pki.DEFAULT_AGENT_DIR
    if not (resolved_agent_dir / "worker.crt").exists():
        console.print(f"[red]No worker cert bundle at {resolved_agent_dir} — enroll from the master first.[/]")
        raise typer.Exit(2)

    if not log_file:
        console.print("[red]--log-file is required.[/]")
        raise typer.Exit(2)

    cfg = ForwarderConfig(
        log_path=pathlib.Path(log_file),
        master_host=resolved_host,
        master_port=master_port,
        agent_dir=resolved_agent_dir,
        state_db=pathlib.Path(state_db) if state_db else None,
    )

    if daemon:
        log.info("forwarder daemonizing master=%s:%d log=%s", resolved_host, master_port, log_file)
        _daemonize()

    log.info("forwarder command invoked master=%s:%d log=%s", resolved_host, master_port, log_file)
    console.print(f"[green]Starting DECNET forwarder → {resolved_host}:{master_port} (mTLS)...[/]")

    async def _main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass
        await run_forwarder(cfg, poll_interval=poll_interval, stop_event=stop)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# `decnet swarm ...` — master-side operator commands (HTTP to local swarmctl)
# ---------------------------------------------------------------------------

swarm_app = typer.Typer(
    name="swarm",
    help="Manage swarm workers (enroll, list, decommission). Requires `decnet swarmctl` running.",
    no_args_is_help=True,
)
app.add_typer(swarm_app, name="swarm")


_DEFAULT_SWARMCTL_URL = "http://127.0.0.1:8770"


def _swarmctl_base_url(url: Optional[str]) -> str:
    import os as _os
    return url or _os.environ.get("DECNET_SWARMCTL_URL", _DEFAULT_SWARMCTL_URL)


def _http_request(method: str, url: str, *, json_body: Optional[dict] = None, timeout: float = 30.0):
    """Tiny sync wrapper around httpx; avoids leaking async into the CLI."""
    import httpx
    try:
        resp = httpx.request(method, url, json=json_body, timeout=timeout)
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
        raise typer.Exit(1)
    return resp


def _deploy_swarm(config: "DecnetConfig", *, dry_run: bool, no_cache: bool) -> None:
    """Shard deckies round-robin across enrolled workers and POST to swarmctl."""
    base = _swarmctl_base_url(None)
    resp = _http_request("GET", base + "/swarm/hosts?host_status=enrolled")
    enrolled = resp.json()
    resp2 = _http_request("GET", base + "/swarm/hosts?host_status=active")
    active = resp2.json()
    # Treat enrolled+active workers as dispatch targets.
    workers = [*enrolled, *active]
    if not workers:
        console.print("[red]No enrolled workers — run `decnet swarm enroll ...` first.[/]")
        raise typer.Exit(1)

    # Round-robin assign deckies to workers by host_uuid (mutate the config's
    # decky entries in-place — DecnetConfig is a pydantic model so we use
    # model_copy on each decky).
    assigned: list = []
    for idx, d in enumerate(config.deckies):
        target = workers[idx % len(workers)]
        assigned.append(d.model_copy(update={"host_uuid": target["uuid"]}))
    config = config.model_copy(update={"deckies": assigned})

    body = {"config": config.model_dump(mode="json"), "dry_run": dry_run, "no_cache": no_cache}
    console.print(f"[cyan]Dispatching {len(config.deckies)} deckies across {len(workers)} worker(s)...[/]")
    # Swarm deploy can be slow (image pulls on each worker) — give it plenty.
    resp3 = _http_request("POST", base + "/swarm/deploy", json_body=body, timeout=900.0)
    results = resp3.json().get("results", [])

    table = Table(title="SWARM deploy results")
    for col in ("worker", "host_uuid", "ok", "detail"):
        table.add_column(col)
    any_failed = False
    for r in results:
        ok = bool(r.get("ok"))
        if not ok:
            any_failed = True
        detail = r.get("detail")
        if isinstance(detail, dict):
            detail = detail.get("status") or "ok"
        table.add_row(
            str(r.get("host_name") or ""),
            str(r.get("host_uuid") or ""),
            "[green]yes[/]" if ok else "[red]no[/]",
            str(detail)[:80],
        )
    console.print(table)
    if any_failed:
        raise typer.Exit(1)


@swarm_app.command("enroll")
def swarm_enroll(
    name: str = typer.Option(..., "--name", help="Short hostname for the worker (also the cert CN)"),
    address: str = typer.Option(..., "--address", help="IP or DNS the master uses to reach the worker"),
    agent_port: int = typer.Option(8765, "--agent-port", help="Worker agent TCP port"),
    sans: Optional[str] = typer.Option(None, "--sans", help="Comma-separated extra SANs for the worker cert"),
    notes: Optional[str] = typer.Option(None, "--notes", help="Free-form operator notes"),
    out_dir: Optional[str] = typer.Option(None, "--out-dir", help="Write the bundle (ca.crt/worker.crt/worker.key) to this dir for scp"),
    updater: bool = typer.Option(False, "--updater", help="Also issue an updater-identity cert (CN=updater@<name>) for the remote self-updater"),
    url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL (default: 127.0.0.1:8770)"),
) -> None:
    """Issue a mTLS bundle for a new worker and register it in the swarm."""
    import pathlib as _pathlib

    body: dict = {"name": name, "address": address, "agent_port": agent_port}
    if sans:
        body["sans"] = [s.strip() for s in sans.split(",") if s.strip()]
    if notes:
        body["notes"] = notes
    if updater:
        body["issue_updater_bundle"] = True

    resp = _http_request("POST", _swarmctl_base_url(url) + "/swarm/enroll", json_body=body)
    data = resp.json()

    console.print(f"[green]Enrolled worker:[/] {data['name']}  "
                  f"[dim]uuid=[/]{data['host_uuid']}  "
                  f"[dim]fingerprint=[/]{data['fingerprint']}")
    if data.get("updater"):
        console.print(f"[green]  + updater identity[/] "
                      f"[dim]fingerprint=[/]{data['updater']['fingerprint']}")

    if out_dir:
        target = _pathlib.Path(out_dir).expanduser()
        target.mkdir(parents=True, exist_ok=True)
        (target / "ca.crt").write_text(data["ca_cert_pem"])
        (target / "worker.crt").write_text(data["worker_cert_pem"])
        (target / "worker.key").write_text(data["worker_key_pem"])
        for leaf in ("worker.key",):
            try:
                (target / leaf).chmod(0o600)
            except OSError:
                pass
        console.print(f"[cyan]Agent bundle written to[/] {target}")

        if data.get("updater"):
            upd_target = target.parent / f"{target.name}-updater"
            upd_target.mkdir(parents=True, exist_ok=True)
            (upd_target / "ca.crt").write_text(data["ca_cert_pem"])
            (upd_target / "updater.crt").write_text(data["updater"]["updater_cert_pem"])
            (upd_target / "updater.key").write_text(data["updater"]["updater_key_pem"])
            try:
                (upd_target / "updater.key").chmod(0o600)
            except OSError:
                pass
            console.print(f"[cyan]Updater bundle written to[/] {upd_target}")
            console.print("[dim]Ship the agent dir to ~/.decnet/agent/ and the updater dir to ~/.decnet/updater/ on the worker.[/]")
        else:
            console.print("[dim]Ship this directory to the worker at ~/.decnet/agent/ (or wherever `decnet agent --agent-dir` points).[/]")
    else:
        console.print("[yellow]No --out-dir given — bundle PEMs are in the JSON response; persist them before leaving this shell.[/]")


@swarm_app.command("list")
def swarm_list(
    host_status: Optional[str] = typer.Option(None, "--status", help="Filter by status (enrolled|active|unreachable|decommissioned)"),
    url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
) -> None:
    """List enrolled workers."""
    q = f"?host_status={host_status}" if host_status else ""
    resp = _http_request("GET", _swarmctl_base_url(url) + "/swarm/hosts" + q)
    rows = resp.json()
    if not rows:
        console.print("[dim]No workers enrolled.[/]")
        return
    table = Table(title="DECNET swarm workers")
    for col in ("name", "address", "port", "status", "last heartbeat", "enrolled"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r.get("name") or "",
            r.get("address") or "",
            str(r.get("agent_port") or ""),
            r.get("status") or "",
            str(r.get("last_heartbeat") or "—"),
            str(r.get("enrolled_at") or "—"),
        )
    console.print(table)


@swarm_app.command("check")
def swarm_check(
    url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
) -> None:
    """Actively probe every enrolled worker and refresh status + last_heartbeat."""
    resp = _http_request("POST", _swarmctl_base_url(url) + "/swarm/check", timeout=60.0)
    payload = resp.json()
    results = payload.get("results", [])

    if json_out:
        console.print_json(data=payload)
        return

    if not results:
        console.print("[dim]No workers enrolled.[/]")
        return

    table = Table(title="DECNET swarm check")
    for col in ("name", "address", "reachable", "detail"):
        table.add_column(col)
    for r in results:
        reachable = r.get("reachable")
        mark = "[green]yes[/]" if reachable else "[red]no[/]"
        detail = r.get("detail")
        detail_str = "—"
        if isinstance(detail, dict):
            detail_str = detail.get("status") or ", ".join(f"{k}={v}" for k, v in detail.items())
        elif detail is not None:
            detail_str = str(detail)
        table.add_row(
            r.get("name") or "",
            r.get("address") or "",
            mark,
            detail_str,
        )
    console.print(table)


@swarm_app.command("update")
def swarm_update(
    host: Optional[str] = typer.Option(None, "--host", help="Target worker (name or UUID). Omit with --all."),
    all_hosts: bool = typer.Option(False, "--all", help="Push to every enrolled worker."),
    include_self: bool = typer.Option(False, "--include-self", help="Also push to each updater's /update-self after a successful agent update."),
    root: Optional[str] = typer.Option(None, "--root", help="Source tree to tar (default: CWD)."),
    exclude: list[str] = typer.Option([], "--exclude", help="Additional exclude glob. Repeatable."),
    updater_port: int = typer.Option(8766, "--updater-port", help="Port the workers' updater listens on."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Build the tarball and print stats; no network."),
    url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL."),
) -> None:
    """Push the current working tree to workers' self-updaters (with auto-rollback on failure)."""
    import asyncio
    import pathlib as _pathlib

    from decnet.swarm.tar_tree import tar_working_tree, detect_git_sha
    from decnet.swarm.updater_client import UpdaterClient

    if not (host or all_hosts):
        console.print("[red]Supply --host <name> or --all.[/]")
        raise typer.Exit(2)
    if host and all_hosts:
        console.print("[red]--host and --all are mutually exclusive.[/]")
        raise typer.Exit(2)

    base = _swarmctl_base_url(url)
    resp = _http_request("GET", base + "/swarm/hosts")
    rows = resp.json()
    if host:
        targets = [r for r in rows if r.get("name") == host or r.get("uuid") == host]
        if not targets:
            console.print(f"[red]No enrolled worker matching '{host}'.[/]")
            raise typer.Exit(1)
    else:
        targets = [r for r in rows if r.get("status") != "decommissioned"]
    if not targets:
        console.print("[dim]No targets.[/]")
        return

    tree_root = _pathlib.Path(root) if root else _pathlib.Path.cwd()
    sha = detect_git_sha(tree_root)
    console.print(f"[dim]Tarring[/] {tree_root} [dim]sha={sha or '(not a git repo)'}[/]")
    tarball = tar_working_tree(tree_root, extra_excludes=exclude)
    console.print(f"[dim]Tarball size:[/] {len(tarball):,} bytes")

    if dry_run:
        console.print("[yellow]--dry-run: not pushing.[/]")
        for t in targets:
            console.print(f"  would push to [cyan]{t.get('name')}[/] at {t.get('address')}:{updater_port}")
        return

    async def _push_one(h: dict) -> dict:
        name = h.get("name") or h.get("uuid")
        out: dict = {"name": name, "address": h.get("address"), "agent": None, "self": None}
        try:
            async with UpdaterClient(h, updater_port=updater_port) as u:
                r = await u.update(tarball, sha=sha)
                out["agent"] = {"status": r.status_code, "body": r.json() if r.content else {}}
                if r.status_code == 200 and include_self:
                    # Agent first, updater second — see plan.
                    rs = await u.update_self(tarball, sha=sha)
                    # Connection-drop is expected for update-self.
                    out["self"] = {"status": rs.status_code, "body": rs.json() if rs.content else {}}
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    async def _push_all() -> list[dict]:
        return await asyncio.gather(*(_push_one(t) for t in targets))

    results = asyncio.run(_push_all())

    table = Table(title="DECNET swarm update")
    for col in ("host", "address", "agent", "self", "detail"):
        table.add_column(col)
    any_failure = False
    for r in results:
        agent = r.get("agent") or {}
        selff = r.get("self") or {}
        err = r.get("error")
        if err:
            any_failure = True
            table.add_row(r["name"], r.get("address") or "", "[red]error[/]", "—", err)
            continue
        a_status = agent.get("status")
        if a_status == 200:
            agent_cell = "[green]updated[/]"
        elif a_status == 409:
            agent_cell = "[yellow]rolled-back[/]"
            any_failure = True
        else:
            agent_cell = f"[red]{a_status}[/]"
            any_failure = True
        if not include_self:
            self_cell = "—"
        elif selff.get("status") == 200 or selff.get("status") is None:
            self_cell = "[green]ok[/]" if selff else "[dim]skipped[/]"
        else:
            self_cell = f"[red]{selff.get('status')}[/]"
        detail = ""
        body = agent.get("body") or {}
        if isinstance(body, dict):
            detail = body.get("release", {}).get("sha") or body.get("detail", {}).get("error") or ""
        table.add_row(r["name"], r.get("address") or "", agent_cell, self_cell, str(detail)[:80])
    console.print(table)

    if any_failure:
        raise typer.Exit(1)


@swarm_app.command("deckies")
def swarm_deckies(
    host: Optional[str] = typer.Option(None, "--host", help="Filter by worker name or UUID"),
    state: Optional[str] = typer.Option(None, "--state", help="Filter by shard state (pending|running|failed|torn_down)"),
    url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
) -> None:
    """List deployed deckies across the swarm with their owning worker host."""
    base = _swarmctl_base_url(url)

    host_uuid: Optional[str] = None
    if host:
        resp = _http_request("GET", base + "/swarm/hosts")
        rows = resp.json()
        match = next((r for r in rows if r.get("uuid") == host or r.get("name") == host), None)
        if match is None:
            console.print(f"[red]No enrolled worker matching '{host}'.[/]")
            raise typer.Exit(1)
        host_uuid = match["uuid"]

    query = []
    if host_uuid:
        query.append(f"host_uuid={host_uuid}")
    if state:
        query.append(f"state={state}")
    path = "/swarm/deckies" + ("?" + "&".join(query) if query else "")

    resp = _http_request("GET", base + path)
    rows = resp.json()

    if json_out:
        console.print_json(data=rows)
        return

    if not rows:
        console.print("[dim]No deckies deployed.[/]")
        return

    table = Table(title="DECNET swarm deckies")
    for col in ("decky", "host", "address", "state", "services"):
        table.add_column(col)
    for r in rows:
        services = ",".join(r.get("services") or []) or "—"
        state_val = r.get("state") or "pending"
        colored = {
            "running": f"[green]{state_val}[/]",
            "failed": f"[red]{state_val}[/]",
            "pending": f"[yellow]{state_val}[/]",
            "torn_down": f"[dim]{state_val}[/]",
        }.get(state_val, state_val)
        table.add_row(
            r.get("decky_name") or "",
            r.get("host_name") or "<unknown>",
            r.get("host_address") or "",
            colored,
            services,
        )
    console.print(table)


@swarm_app.command("decommission")
def swarm_decommission(
    name: Optional[str] = typer.Option(None, "--name", help="Worker hostname"),
    uuid: Optional[str] = typer.Option(None, "--uuid", help="Worker UUID (skip lookup)"),
    url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirmation"),
) -> None:
    """Remove a worker from the swarm (cascades decky shard rows)."""
    if not (name or uuid):
        console.print("[red]Supply --name or --uuid.[/]")
        raise typer.Exit(2)

    base = _swarmctl_base_url(url)
    target_uuid = uuid
    target_name = name
    if target_uuid is None:
        resp = _http_request("GET", base + "/swarm/hosts")
        rows = resp.json()
        match = next((r for r in rows if r.get("name") == name), None)
        if match is None:
            console.print(f"[red]No enrolled worker named '{name}'.[/]")
            raise typer.Exit(1)
        target_uuid = match["uuid"]
        target_name = match.get("name") or target_name

    if not yes:
        confirm = typer.confirm(f"Decommission worker {target_name!r} ({target_uuid})?", default=False)
        if not confirm:
            console.print("[dim]Aborted.[/]")
            raise typer.Exit(0)

    _http_request("DELETE", f"{base}/swarm/hosts/{target_uuid}")
    console.print(f"[green]Decommissioned {target_name or target_uuid}.[/]")


@app.command()
def deploy(
    mode: str = typer.Option("unihost", "--mode", "-m", help="Deployment mode: unihost | swarm"),
    deckies: Optional[int] = typer.Option(None, "--deckies", "-n", help="Number of deckies to deploy (required without --config)", min=1),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Host NIC (auto-detected if omitted)"),
    subnet: Optional[str] = typer.Option(None, "--subnet", help="LAN subnet CIDR (auto-detected if omitted)"),
    ip_start: Optional[str] = typer.Option(None, "--ip-start", help="First decky IP (auto if omitted)"),
    services: Optional[str] = typer.Option(None, "--services", help="Comma-separated services, e.g. ssh,smb,rdp"),
    randomize_services: bool = typer.Option(False, "--randomize-services", help="Assign random services to each decky"),
    distro: Optional[str] = typer.Option(None, "--distro", help="Comma-separated distro slugs, e.g. debian,ubuntu22,rocky9"),
    randomize_distros: bool = typer.Option(False, "--randomize-distros", help="Assign a random distro to each decky"),
    log_file: Optional[str] = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Host path for the collector to write RFC 5424 logs (e.g. /var/log/decnet/decnet.log)"),
    archetype_name: Optional[str] = typer.Option(None, "--archetype", "-a", help="Machine archetype slug (e.g. linux-server, windows-workstation)"),
    mutate_interval: Optional[int] = typer.Option(30, "--mutate-interval", help="Automatically rotate services every N minutes"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate compose file without starting containers"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Force rebuild all images, ignoring Docker layer cache"),
    parallel: bool = typer.Option(False, "--parallel", help="Build all images concurrently (enables BuildKit, separates build from up)"),
    ipvlan: bool = typer.Option(False, "--ipvlan", help="Use IPvlan L2 instead of MACVLAN (required on WiFi interfaces)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to INI config file"),
    api: bool = typer.Option(False, "--api", help="Start the FastAPI backend to ingest and serve logs"),
    api_port: int = typer.Option(8000, "--api-port", help="Port for the backend API"),
    daemon: bool = typer.Option(False, "--daemon", help="Detach to background as a daemon process"),
) -> None:
    """Deploy deckies to the LAN."""
    import os

    _require_master_mode("deploy")
    if daemon:
        log.info("deploy daemonizing mode=%s deckies=%s", mode, deckies)
        _daemonize()

    log.info("deploy command invoked mode=%s deckies=%s dry_run=%s", mode, deckies, dry_run)
    if mode not in ("unihost", "swarm"):
        console.print("[red]--mode must be 'unihost' or 'swarm'[/]")
        raise typer.Exit(1)

    # ------------------------------------------------------------------ #
    # Config-file path                                                     #
    # ------------------------------------------------------------------ #
    if config_file:
        try:
            ini = load_ini(config_file)
        except FileNotFoundError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(1)

        iface = interface or ini.interface or detect_interface()
        subnet_cidr = subnet or ini.subnet
        effective_gateway = ini.gateway
        if subnet_cidr is None:
            subnet_cidr, effective_gateway = detect_subnet(iface)
        elif effective_gateway is None:
            _, effective_gateway = detect_subnet(iface)

        host_ip = get_host_ip(iface)
        console.print(f"[dim]Config:[/] {config_file}  [dim]Interface:[/] {iface}  "
                      f"[dim]Subnet:[/] {subnet_cidr}  [dim]Gateway:[/] {effective_gateway}  "
                      f"[dim]Host IP:[/] {host_ip}")

        if ini.custom_services:
            from decnet.custom_service import CustomService
            from decnet.services.registry import register_custom_service
            for cs in ini.custom_services:
                register_custom_service(
                    CustomService(
                        name=cs.name,
                        image=cs.image,
                        exec_cmd=cs.exec_cmd,
                        ports=cs.ports,
                    )
                )

        effective_log_file = log_file
        try:
            decky_configs = build_deckies_from_ini(
                ini, subnet_cidr, effective_gateway, host_ip, randomize_services, cli_mutate_interval=mutate_interval
            )
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(1)
    # ------------------------------------------------------------------ #
    # Classic CLI path                                                     #
    # ------------------------------------------------------------------ #
    else:
        if deckies is None:
            console.print("[red]--deckies is required when --config is not used.[/]")
            raise typer.Exit(1)

        services_list = [s.strip() for s in services.split(",")] if services else None
        if services_list:
            known = set(all_service_names())
            unknown = [s for s in services_list if s not in known]
            if unknown:
                console.print(f"[red]Unknown service(s): {unknown}. Available: {all_service_names()}[/]")
                raise typer.Exit(1)

        arch: Archetype | None = None
        if archetype_name:
            try:
                arch = get_archetype(archetype_name)
            except ValueError as e:
                console.print(f"[red]{e}[/]")
                raise typer.Exit(1)

        if not services_list and not randomize_services and not arch:
            console.print("[red]Specify --services, --archetype, or --randomize-services.[/]")
            raise typer.Exit(1)

        iface = interface or detect_interface()
        if subnet is None:
            subnet_cidr, effective_gateway = detect_subnet(iface)
        else:
            subnet_cidr = subnet
            _, effective_gateway = detect_subnet(iface)

        host_ip = get_host_ip(iface)
        console.print(f"[dim]Interface:[/] {iface}  [dim]Subnet:[/] {subnet_cidr}  "
                      f"[dim]Gateway:[/] {effective_gateway}  [dim]Host IP:[/] {host_ip}")

        distros_list = [d.strip() for d in distro.split(",")] if distro else None
        if distros_list:
            try:
                for slug in distros_list:
                    get_distro(slug)
            except ValueError as e:
                console.print(f"[red]{e}[/]")
                raise typer.Exit(1)

        ips = allocate_ips(subnet_cidr, effective_gateway, host_ip, deckies, ip_start)
        decky_configs = build_deckies(
            deckies, ips, services_list, randomize_services,
            distros_explicit=distros_list, randomize_distros=randomize_distros,
            archetype=arch, mutate_interval=mutate_interval,
        )
        effective_log_file = log_file

    if api and not effective_log_file:
        effective_log_file = os.path.join(os.getcwd(), "decnet.log")
        console.print(f"[cyan]API mode enabled: defaulting log-file to {effective_log_file}[/]")

    config = DecnetConfig(
        mode=mode,
        interface=iface,
        subnet=subnet_cidr,
        gateway=effective_gateway,
        deckies=decky_configs,
        log_file=effective_log_file,
        ipvlan=ipvlan,
        mutate_interval=mutate_interval,
    )

    log.debug("deploy: config built deckies=%d interface=%s subnet=%s", len(config.deckies), config.interface, config.subnet)

    if mode == "swarm":
        _deploy_swarm(config, dry_run=dry_run, no_cache=no_cache)
        if dry_run:
            log.info("deploy: swarm dry-run complete, no workers dispatched")
        else:
            log.info("deploy: swarm deployment complete deckies=%d", len(config.deckies))
        return

    from decnet.engine import deploy as _deploy
    _deploy(config, dry_run=dry_run, no_cache=no_cache, parallel=parallel)
    if dry_run:
        log.info("deploy: dry-run complete, no containers started")
    else:
        log.info("deploy: deployment complete deckies=%d", len(config.deckies))

    if mutate_interval is not None and not dry_run:
        import subprocess  # nosec B404
        import sys
        console.print(f"[green]Starting DECNET Mutator watcher in the background (interval: {mutate_interval}m)...[/]")
        try:
            subprocess.Popen(  # nosec B603
                [sys.executable, "-m", "decnet.cli", "mutate", "--watch"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start mutator watcher.[/]")

    if effective_log_file and not dry_run and not api:
        import subprocess  # nosec B404
        import sys
        from pathlib import Path as _Path
        _collector_err = _Path(effective_log_file).with_suffix(".collector.log")
        console.print(f"[bold cyan]Starting log collector[/] → {effective_log_file}")
        subprocess.Popen(  # nosec B603
            [sys.executable, "-m", "decnet.cli", "collect", "--log-file", str(effective_log_file)],
            stdin=subprocess.DEVNULL,
            stdout=open(_collector_err, "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    if api and not dry_run:
        import subprocess  # nosec B404
        import sys
        console.print(f"[green]Starting DECNET API on port {api_port}...[/]")
        _env: dict[str, str] = os.environ.copy()
        _env["DECNET_INGEST_LOG_FILE"] = str(effective_log_file or "")
        try:
            subprocess.Popen(  # nosec B603
                [sys.executable, "-m", "uvicorn", "decnet.web.api:app", "--host", DECNET_API_HOST, "--port", str(api_port)],
                env=_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            console.print(f"[dim]API running at http://{DECNET_API_HOST}:{api_port}[/]")
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start API. Ensure 'uvicorn' is installed in the current environment.[/]")

    if effective_log_file and not dry_run:
        import subprocess  # nosec B404
        import sys
        console.print("[bold cyan]Starting DECNET-PROBER[/] (auto-discovers attackers from log stream)")
        try:
            _prober_args = [
                sys.executable, "-m", "decnet.cli", "probe",
                "--daemon",
                "--log-file", str(effective_log_file),
            ]
            subprocess.Popen(  # nosec B603
                _prober_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start DECNET-PROBER.[/]")

    if effective_log_file and not dry_run:
        import subprocess  # nosec B404
        import sys
        console.print("[bold cyan]Starting DECNET-PROFILER[/] (builds attacker profiles from log stream)")
        try:
            subprocess.Popen(  # nosec B603
                [sys.executable, "-m", "decnet.cli", "profiler", "--daemon"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start DECNET-PROFILER.[/]")

    if effective_log_file and not dry_run:
        import subprocess  # nosec B404
        import sys
        console.print("[bold cyan]Starting DECNET-SNIFFER[/] (passive network capture)")
        try:
            subprocess.Popen(  # nosec B603
                [sys.executable, "-m", "decnet.cli", "sniffer",
                 "--daemon",
                 "--log-file", str(effective_log_file)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start DECNET-SNIFFER.[/]")


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


# Each entry: (display_name, detection_fn, launch_args_fn)
# launch_args_fn receives log_file and returns the Popen argv list.
def _service_registry(log_file: str) -> list[tuple[str, callable, list[str]]]:
    """Return the microservice registry for health-check and relaunch."""
    import sys

    _py = sys.executable
    return [
        (
            "Collector",
            lambda cmd: "decnet.cli" in cmd and "collect" in cmd,
            [_py, "-m", "decnet.cli", "collect", "--daemon", "--log-file", log_file],
        ),
        (
            "Mutator",
            lambda cmd: "decnet.cli" in cmd and "mutate" in cmd and "--watch" in cmd,
            [_py, "-m", "decnet.cli", "mutate", "--daemon", "--watch"],
        ),
        (
            "Prober",
            lambda cmd: "decnet.cli" in cmd and "probe" in cmd,
            [_py, "-m", "decnet.cli", "probe", "--daemon", "--log-file", log_file],
        ),
        (
            "Profiler",
            lambda cmd: "decnet.cli" in cmd and "profiler" in cmd,
            [_py, "-m", "decnet.cli", "profiler", "--daemon"],
        ),
        (
            "Sniffer",
            lambda cmd: "decnet.cli" in cmd and "sniffer" in cmd,
            [_py, "-m", "decnet.cli", "sniffer", "--daemon", "--log-file", log_file],
        ),
        (
            "API",
            lambda cmd: "uvicorn" in cmd and "decnet.web.api:app" in cmd,
            [_py, "-m", "uvicorn", "decnet.web.api:app",
             "--host", DECNET_API_HOST, "--port", str(DECNET_API_PORT)],
        ),
    ]


@app.command()
def redeploy(
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to the DECNET log file"),
) -> None:
    """Check running DECNET services and relaunch any that are down."""
    import subprocess  # nosec B404

    log.info("redeploy: checking services")
    registry = _service_registry(str(log_file))

    table = Table(title="DECNET Services", show_lines=True)
    table.add_column("Service", style="bold cyan")
    table.add_column("Status")
    table.add_column("PID", style="dim")
    table.add_column("Action")

    relaunched = 0
    for name, match_fn, launch_args in registry:
        pid = _is_running(match_fn)
        if pid is not None:
            table.add_row(name, "[green]UP[/]", str(pid), "—")
        else:
            try:
                subprocess.Popen(  # nosec B603
                    launch_args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                table.add_row(name, "[red]DOWN[/]", "—", "[green]relaunched[/]")
                relaunched += 1
            except (FileNotFoundError, subprocess.SubprocessError) as exc:
                table.add_row(name, "[red]DOWN[/]", "—", f"[red]failed: {exc}[/]")

    console.print(table)
    if relaunched:
        console.print(f"[green]{relaunched} service(s) relaunched.[/]")
    else:
        console.print("[green]All services running.[/]")


@app.command()
def probe(
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path for RFC 5424 syslog + .json output (reads attackers from .json, writes results to both)"),
    interval: int = typer.Option(300, "--interval", "-i", help="Seconds between probe cycles (default: 300)"),
    timeout: float = typer.Option(5.0, "--timeout", help="Per-probe TCP timeout in seconds"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background (used by deploy, no console output)"),
) -> None:
    """Fingerprint attackers (JARM + HASSH + TCP/IP stack) discovered in the log stream."""
    import asyncio
    from decnet.prober import prober_worker

    if daemon:
        log.info("probe daemonizing log_file=%s interval=%d", log_file, interval)
        _daemonize()
        asyncio.run(prober_worker(log_file, interval=interval, timeout=timeout))
        return

    else:
        log.info("probe command invoked log_file=%s interval=%d", log_file, interval)
        console.print(f"[bold cyan]DECNET-PROBER[/] watching {log_file} for attackers (interval: {interval}s)")
        console.print("[dim]Press Ctrl+C to stop[/]")
        try:
            asyncio.run(prober_worker(log_file, interval=interval, timeout=timeout))
        except KeyboardInterrupt:
            console.print("\n[yellow]DECNET-PROBER stopped.[/]")


@app.command()
def collect(
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to write RFC 5424 syslog lines and .json records"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Stream Docker logs from all running decky service containers to a log file."""
    import asyncio
    from decnet.collector import log_collector_worker

    if daemon:
        log.info("collect daemonizing log_file=%s", log_file)
        _daemonize()

    log.info("collect command invoked log_file=%s", log_file)
    console.print(f"[bold cyan]Collector starting[/] → {log_file}")
    asyncio.run(log_collector_worker(log_file))


@app.command()
def mutate(
    watch: bool = typer.Option(False, "--watch", "-w", help="Run continuously and mutate deckies according to their interval"),
    decky_name: Optional[str] = typer.Option(None, "--decky", help="Force mutate a specific decky immediately"),
    force_all: bool = typer.Option(False, "--all", help="Force mutate all deckies immediately"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Manually trigger or continuously watch for decky mutation."""
    import asyncio
    from decnet.mutator import mutate_decky, mutate_all, run_watch_loop
    from decnet.web.dependencies import repo

    if daemon:
        log.info("mutate daemonizing watch=%s", watch)
        _daemonize()

    async def _run() -> None:
        await repo.initialize()
        if watch:
            await run_watch_loop(repo)
        elif decky_name:
            await mutate_decky(decky_name, repo)
        elif force_all:
            await mutate_all(force=True, repo=repo)
        else:
            await mutate_all(force=False, repo=repo)

    asyncio.run(_run())


@app.command()
def status() -> None:
    """Show running deckies and their status."""
    log.info("status command invoked")
    from decnet.engine import status as _status
    _status()

    registry = _service_registry(str(DECNET_INGEST_LOG_FILE))
    # On agents, the Mutator runs master-side only (it schedules decky
    # respawns across the swarm) and the API is never shipped. Hide those
    # rows so operators aren't chasing permanent DOWN entries.
    if _agent_mode_active():
        registry = [r for r in registry if r[0] not in {"Mutator", "API"}]
    svc_table = Table(title="DECNET Services", show_lines=True)
    svc_table.add_column("Service", style="bold cyan")
    svc_table.add_column("Status")
    svc_table.add_column("PID", style="dim")

    for name, match_fn, _launch_args in registry:
        pid = _is_running(match_fn)
        if pid is not None:
            svc_table.add_row(name, "[green]UP[/]", str(pid))
        else:
            svc_table.add_row(name, "[red]DOWN[/]", "—")

    console.print(svc_table)


@app.command()
def teardown(
    all_: bool = typer.Option(False, "--all", help="Tear down all deckies and remove network"),
    id_: Optional[str] = typer.Option(None, "--id", help="Tear down a specific decky by name"),
) -> None:
    """Stop and remove deckies."""
    _require_master_mode("teardown")
    if not all_ and not id_:
        console.print("[red]Specify --all or --id <name>.[/]")
        raise typer.Exit(1)

    log.info("teardown command invoked all=%s id=%s", all_, id_)
    from decnet.engine import teardown as _teardown
    _teardown(decky_id=id_)
    log.info("teardown complete all=%s id=%s", all_, id_)

    if all_:
        _kill_all_services()


@app.command(name="services")
def list_services() -> None:
    """List all registered honeypot service plugins."""
    svcs = all_services()
    table = Table(title="Available Services", show_lines=True)
    table.add_column("Name", style="bold cyan")
    table.add_column("Ports")
    table.add_column("Image")
    for name, svc in sorted(svcs.items()):
        table.add_row(name, ", ".join(str(p) for p in svc.ports), svc.default_image)
    console.print(table)


@app.command(name="distros")
def list_distros() -> None:
    """List all available OS distro profiles for deckies."""
    table = Table(title="Available Distro Profiles", show_lines=True)
    table.add_column("Slug", style="bold cyan")
    table.add_column("Display Name")
    table.add_column("Docker Image", style="dim")
    for slug, profile in sorted(all_distros().items()):
        table.add_row(slug, profile.display_name, profile.image)
    console.print(table)


@app.command(name="correlate")
def correlate(
    log_file: Optional[str] = typer.Option(None, "--log-file", "-f", help="Path to DECNET syslog file to analyse"),
    min_deckies: int = typer.Option(2, "--min-deckies", "-m", help="Minimum number of distinct deckies an IP must touch to be reported"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table | json | syslog"),
    emit_syslog: bool = typer.Option(False, "--emit-syslog", help="Also print traversal events as RFC 5424 lines (for SIEM piping)"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Analyse logs for cross-decky traversals and print the attacker movement graph."""
    import sys
    import json as _json
    from pathlib import Path
    from decnet.correlation.engine import CorrelationEngine

    if daemon:
        log.info("correlate daemonizing log_file=%s", log_file)
        _daemonize()

    engine = CorrelationEngine()

    if log_file:
        path = Path(log_file)
        if not path.exists():
            console.print(f"[red]Log file not found: {log_file}[/]")
            raise typer.Exit(1)
        engine.ingest_file(path)
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            engine.ingest(line)
    else:
        console.print("[red]Provide --log-file or pipe log data via stdin.[/]")
        raise typer.Exit(1)

    traversals = engine.traversals(min_deckies)

    if output == "json":
        console.print_json(_json.dumps(engine.report_json(min_deckies), indent=2))
    elif output == "syslog":
        for line in engine.traversal_syslog_lines(min_deckies):
            typer.echo(line)
    else:
        if not traversals:
            console.print(
                f"[yellow]No traversals detected "
                f"(min_deckies={min_deckies}, events_indexed={engine.events_indexed}).[/]"
            )
        else:
            console.print(engine.report_table(min_deckies))
            console.print(
                f"[dim]Parsed {engine.lines_parsed} lines · "
                f"indexed {engine.events_indexed} events · "
                f"{len(engine.all_attackers())} unique IPs · "
                f"[bold]{len(traversals)}[/] traversal(s)[/]"
            )

    if emit_syslog:
        for line in engine.traversal_syslog_lines(min_deckies):
            typer.echo(line)


@app.command(name="archetypes")
def list_archetypes() -> None:
    """List all machine archetype profiles."""
    table = Table(title="Machine Archetypes", show_lines=True)
    table.add_column("Slug", style="bold cyan")
    table.add_column("Display Name")
    table.add_column("Default Services", style="green")
    table.add_column("Description", style="dim")
    for slug, arch in sorted(all_archetypes().items()):
        table.add_row(
            slug,
            arch.display_name,
            ", ".join(arch.services),
            arch.description,
        )
    console.print(table)


@app.command(name="web")
def serve_web(
    web_port: int = typer.Option(DECNET_WEB_PORT, "--web-port", help="Port to serve the DECNET Web Dashboard"),
    host: str = typer.Option(DECNET_WEB_HOST, "--host", help="Host IP to serve the Web Dashboard"),
    api_port: int = typer.Option(DECNET_API_PORT, "--api-port", help="Port the DECNET API is listening on"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Serve the DECNET Web Dashboard frontend.

    Proxies /api/* requests to the API server so the frontend can use
    relative URLs (/api/v1/...) with no CORS configuration required.
    """
    import http.client
    import http.server
    import socketserver
    from pathlib import Path

    dist_dir = Path(__file__).parent.parent / "decnet_web" / "dist"

    if not dist_dir.exists():
        console.print(f"[red]Frontend build not found at {dist_dir}. Make sure you run 'npm run build' inside 'decnet_web'.[/]")
        raise typer.Exit(1)

    if daemon:
        log.info("web daemonizing host=%s port=%d api_port=%d", host, web_port, api_port)
        _daemonize()

    _api_port = api_port

    class SPAHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/"):
                self._proxy("GET")
                return
            path = self.translate_path(self.path)
            if not Path(path).exists() or Path(path).is_dir():
                self.path = "/index.html"
            return super().do_GET()

        def do_POST(self):
            if self.path.startswith("/api/"):
                self._proxy("POST")
                return
            self.send_error(405)

        def do_PUT(self):
            if self.path.startswith("/api/"):
                self._proxy("PUT")
                return
            self.send_error(405)

        def do_DELETE(self):
            if self.path.startswith("/api/"):
                self._proxy("DELETE")
                return
            self.send_error(405)

        def _proxy(self, method: str) -> None:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length else None

            forward = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "connection")}

            try:
                conn = http.client.HTTPConnection("127.0.0.1", _api_port, timeout=120)
                conn.request(method, self.path, body=body, headers=forward)
                resp = conn.getresponse()

                self.send_response(resp.status)
                for key, val in resp.getheaders():
                    if key.lower() not in ("connection", "transfer-encoding"):
                        self.send_header(key, val)
                self.end_headers()

                # Disable socket timeout for SSE streams — they are
                # long-lived by design and the 120s timeout would kill them.
                content_type = resp.getheader("Content-Type", "")
                if "text/event-stream" in content_type:
                    conn.sock.settimeout(None)

                # read1() returns bytes immediately available in the buffer
                # without blocking for more.  Plain read(4096) waits until
                # 4096 bytes accumulate — fatal for SSE where each event
                # is only ~100-500 bytes.
                _read = getattr(resp, "read1", resp.read)
                while True:
                    chunk = _read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except Exception as exc:
                log.warning("web proxy error %s %s: %s", method, self.path, exc)
                self.send_error(502, f"API proxy error: {exc}")
            finally:
                try:
                    conn.close()
                except Exception:  # nosec B110 — best-effort conn cleanup
                    pass

        def log_message(self, fmt: str, *args: object) -> None:
            log.debug("web %s", fmt % args)

    import os
    os.chdir(dist_dir)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, web_port), SPAHTTPRequestHandler) as httpd:
        console.print(f"[green]Serving DECNET Web Dashboard on http://{host}:{web_port}[/]")
        console.print(f"[dim]Proxying /api/* → http://127.0.0.1:{_api_port}[/]")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[dim]Shutting down dashboard server.[/]")

@app.command(name="profiler")
def profiler_cmd(
    interval: int = typer.Option(30, "--interval", "-i", help="Seconds between profile rebuild cycles"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Run the attacker profiler as a standalone microservice."""
    import asyncio
    from decnet.profiler import attacker_profile_worker
    from decnet.web.dependencies import repo

    if daemon:
        log.info("profiler daemonizing interval=%d", interval)
        _daemonize()

    log.info("profiler starting interval=%d", interval)
    console.print(f"[bold cyan]Profiler starting[/] (interval: {interval}s)")

    async def _run() -> None:
        await repo.initialize()
        await attacker_profile_worker(repo, interval=interval)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Profiler stopped.[/]")


@app.command(name="sniffer")
def sniffer_cmd(
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to write captured syslog + JSON records"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Run the network sniffer as a standalone microservice."""
    import asyncio
    from decnet.sniffer import sniffer_worker

    if daemon:
        log.info("sniffer daemonizing log_file=%s", log_file)
        _daemonize()

    log.info("sniffer starting log_file=%s", log_file)
    console.print(f"[bold cyan]Sniffer starting[/] → {log_file}")

    try:
        asyncio.run(sniffer_worker(log_file))
    except KeyboardInterrupt:
        console.print("\n[yellow]Sniffer stopped.[/]")


_DB_RESET_TABLES: tuple[str, ...] = (
    # Order matters for DROP TABLE: child FKs first.
    # - attacker_behavior FK-references attackers.
    # - decky_shards FK-references swarm_hosts.
    "attacker_behavior",
    "attackers",
    "logs",
    "bounty",
    "state",
    "users",
    "decky_shards",
    "swarm_hosts",
)


async def _db_reset_mysql_async(dsn: str, mode: str, confirm: bool) -> None:
    """Inspect + (optionally) wipe a MySQL database.  Pulled out of the CLI
    wrapper so tests can drive it without spawning a Typer runner."""
    from urllib.parse import urlparse
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    db_name = urlparse(dsn).path.lstrip("/") or "(default)"
    engine = create_async_engine(dsn)
    try:
        # Collect current row counts per table.  Missing tables yield -1.
        rows: dict[str, int] = {}
        async with engine.connect() as conn:
            for tbl in _DB_RESET_TABLES:
                try:
                    result = await conn.execute(text(f"SELECT COUNT(*) FROM `{tbl}`"))  # nosec B608
                    rows[tbl] = result.scalar() or 0
                except Exception:  # noqa: BLE001 — ProgrammingError for missing table varies by driver
                    rows[tbl] = -1

        summary = Table(title=f"DECNET MySQL reset — database `{db_name}` (mode={mode})")
        summary.add_column("Table", style="cyan")
        summary.add_column("Rows", justify="right")
        for tbl, count in rows.items():
            summary.add_row(tbl, "[dim]missing[/]" if count < 0 else f"{count:,}")
        console.print(summary)

        if not confirm:
            console.print(
                "[yellow]Dry-run only.  Re-run with [bold]--i-know-what-im-doing[/] "
                "to actually execute.[/]"
            )
            return

        # Destructive phase.  FK checks off so TRUNCATE/DROP works in any order.
        async with engine.begin() as conn:
            await conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
            for tbl in _DB_RESET_TABLES:
                if rows.get(tbl, -1) < 0:
                    continue  # skip absent tables silently
                if mode == "truncate":
                    await conn.execute(text(f"TRUNCATE TABLE `{tbl}`"))
                    console.print(f"[green]✓ TRUNCATE {tbl}[/]")
                else:  # drop-tables
                    await conn.execute(text(f"DROP TABLE `{tbl}`"))
                    console.print(f"[green]✓ DROP TABLE {tbl}[/]")
            await conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))

        console.print(f"[bold green]Done. Database `{db_name}` reset ({mode}).[/]")
    finally:
        await engine.dispose()


@app.command(name="db-reset")
def db_reset(
    i_know: bool = typer.Option(
        False,
        "--i-know-what-im-doing",
        help="Required to actually execute. Without it, the command runs in dry-run mode.",
    ),
    mode: str = typer.Option(
        "truncate",
        "--mode",
        help="truncate (wipe rows, keep schema) | drop-tables (DROP TABLE for each DECNET table)",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        help="Override DECNET_DB_URL for this invocation (e.g. when cleanup needs admin creds).",
    ),
) -> None:
    """Wipe the MySQL database used by the DECNET dashboard.

    Destructive. Runs dry by default — pass --i-know-what-im-doing to commit.
    Only supported against MySQL; refuses to operate on SQLite.
    """
    import asyncio
    import os

    if mode not in ("truncate", "drop-tables"):
        console.print(f"[red]Invalid --mode '{mode}'. Expected: truncate | drop-tables.[/]")
        raise typer.Exit(2)

    db_type = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()
    if db_type != "mysql":
        console.print(
            f"[red]db-reset is MySQL-only (DECNET_DB_TYPE='{db_type}'). "
            f"For SQLite, just delete the decnet.db file.[/]"
        )
        raise typer.Exit(2)

    dsn = url or os.environ.get("DECNET_DB_URL")
    if not dsn:
        # Fall back to component env vars (DECNET_DB_HOST/PORT/NAME/USER/PASSWORD).
        from decnet.web.db.mysql.database import build_mysql_url
        try:
            dsn = build_mysql_url()
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(2) from e

    log.info("db-reset invoked mode=%s confirm=%s", mode, i_know)
    try:
        asyncio.run(_db_reset_mysql_async(dsn, mode=mode, confirm=i_know))
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]db-reset failed: {e}[/]")
        raise typer.Exit(1) from e


# ───────────────────────────────────────────────────────────────────────────
# Role-based CLI gating.
#
# MAINTAINERS: when you add a new Typer command (or add_typer group) that is
# master-only, register its name in MASTER_ONLY_COMMANDS / MASTER_ONLY_GROUPS
# below. The gate is the only thing that:
#   (a) hides the command from `decnet --help` on worker hosts, and
#   (b) prevents a misconfigured worker from invoking master-side logic.
# Forgetting to register a new command is a role-boundary bug. Grep for
# MASTER_ONLY when touching command registration.
#
# Worker-legitimate commands (NOT in these sets): agent, updater, forwarder,
# status, collect, probe, profiler, sniffer. Agents run deckies locally and
# should be able to inspect them + run the per-host microservices (collector
# streams container logs, prober/profiler characterize attackers hitting
# this host, sniffer captures traffic). Mutator stays master-only because
# it orchestrates respawns across the swarm.
# ───────────────────────────────────────────────────────────────────────────
MASTER_ONLY_COMMANDS: frozenset[str] = frozenset({
    "api", "swarmctl", "deploy", "redeploy", "teardown",
    "mutate", "listener",
    "services", "distros", "correlate", "archetypes", "web",
    "db-reset",
})
MASTER_ONLY_GROUPS: frozenset[str] = frozenset({"swarm"})


def _agent_mode_active() -> bool:
    """True when the host is configured as an agent AND master commands are
    disallowed (the default for agents). Workers overriding this explicitly
    set DECNET_DISALLOW_MASTER=false to opt into hybrid use."""
    import os
    mode = os.environ.get("DECNET_MODE", "master").lower()
    disallow = os.environ.get("DECNET_DISALLOW_MASTER", "true").lower() == "true"
    return mode == "agent" and disallow


def _require_master_mode(command_name: str) -> None:
    """Defence-in-depth: called at the top of every master-only command body.

    The registration-time gate in _gate_commands_by_mode() already hides
    these commands from Typer's dispatch table, but this check protects
    against direct function imports (e.g. from tests or third-party tools)
    that would bypass Typer entirely."""
    if _agent_mode_active():
        console.print(
            f"[red]`decnet {command_name}` is a master-only command; this host "
            f"is configured as an agent (DECNET_MODE=agent).[/]"
        )
        raise typer.Exit(1)


def _gate_commands_by_mode(_app: typer.Typer) -> None:
    if not _agent_mode_active():
        return
    _app.registered_commands = [
        c for c in _app.registered_commands
        if (c.name or c.callback.__name__) not in MASTER_ONLY_COMMANDS
    ]
    _app.registered_groups = [
        g for g in _app.registered_groups
        if g.name not in MASTER_ONLY_GROUPS
    ]


_gate_commands_by_mode(app)


if __name__ == '__main__':  # pragma: no cover
    app()
