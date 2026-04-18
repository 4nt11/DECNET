"""
DECNET CLI — entry point for all commands.

Usage:
  decnet deploy --mode unihost --deckies 5 --randomize-services
  decnet status
  decnet teardown [--all | --id decky-01]
  decnet services
"""

import signal
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
) -> None:
    """Run the DECNET SWARM controller (master-side, separate process from `decnet api`)."""
    import subprocess  # nosec B404
    import sys
    import os
    import signal

    if daemon:
        log.info("swarmctl daemonizing host=%s port=%d", host, port)
        _daemonize()

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
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
) -> None:
    """Run the DECNET SWARM worker agent (requires a cert bundle in ~/.decnet/agent/)."""
    from decnet.agent import server as _agent_server

    if daemon:
        log.info("agent daemonizing host=%s port=%d", host, port)
        _daemonize()

    log.info("agent command invoked host=%s port=%d", host, port)
    console.print(f"[green]Starting DECNET worker agent on {host}:{port} (mTLS)...[/]")
    rc = _agent_server.run(host, port)
    if rc != 0:
        raise typer.Exit(rc)


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
    # Order matters for DROP TABLE: attacker_behavior FK-references attackers.
    "attacker_behavior",
    "attackers",
    "logs",
    "bounty",
    "state",
    "users",
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


if __name__ == '__main__':  # pragma: no cover
    app()
