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

from decnet.env import (
    DECNET_API_HOST,
    DECNET_API_PORT,
    DECNET_INGEST_LOG_FILE,
    DECNET_WEB_HOST,
    DECNET_WEB_PORT,
)
from decnet.archetypes import Archetype, all_archetypes, get_archetype
from decnet.config import (
    DeckyConfig,
    DecnetConfig,
    random_hostname,
)
from decnet.distros import all_distros, get_distro
from decnet.fleet import all_service_names, build_deckies, build_deckies_from_ini
from decnet.ini_loader import IniConfig, load_ini
from decnet.network import detect_interface, detect_subnet, allocate_ips, get_host_ip
from decnet.services.registry import all_services

app = typer.Typer(
    name="decnet",
    help="Deploy a deception network of honeypot deckies on your LAN.",
    no_args_is_help=True,
)
console = Console()


def _kill_api() -> None:
    """Find and kill any running DECNET API (uvicorn) or mutator processes."""
    import psutil
    import os

    _killed: bool = False
    for _proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            _cmd = _proc.info['cmdline']
            if not _cmd:
                continue
            if "uvicorn" in _cmd and "decnet.web.api:app" in _cmd:
                console.print(f"[yellow]Stopping DECNET API (PID {_proc.info['pid']})...[/]")
                os.kill(_proc.info['pid'], signal.SIGTERM)
                _killed = True
            elif "decnet.cli" in _cmd and "mutate" in _cmd and "--watch" in _cmd:
                console.print(f"[yellow]Stopping DECNET Mutator Watcher (PID {_proc.info['pid']})...[/]")
                os.kill(_proc.info['pid'], signal.SIGTERM)
                _killed = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if _killed:
        console.print("[green]Background processes stopped.[/]")


@app.command()
def api(
    port: int = typer.Option(DECNET_API_PORT, "--port", help="Port for the backend API"),
    host: str = typer.Option(DECNET_API_HOST, "--host", help="Host IP for the backend API"),
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Path to the DECNET log file to monitor"),
) -> None:
    """Run the DECNET API and Web Dashboard in standalone mode."""
    import subprocess  # nosec B404
    import sys
    import os

    console.print(f"[green]Starting DECNET API on {host}:{port}...[/]")
    _env: dict[str, str] = os.environ.copy()
    _env["DECNET_INGEST_LOG_FILE"] = str(log_file)
    try:
        subprocess.run(  # nosec B603 B404
            [sys.executable, "-m", "uvicorn", "decnet.web.api:app", "--host", host, "--port", str(port)],
            env=_env
        )
    except KeyboardInterrupt:
        pass
    except (FileNotFoundError, subprocess.SubprocessError):
        console.print("[red]Failed to start API. Ensure 'uvicorn' is installed in the current environment.[/]")


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
) -> None:
    """Deploy deckies to the LAN."""
    import os
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

    from decnet.engine import deploy as _deploy
    _deploy(config, dry_run=dry_run, no_cache=no_cache, parallel=parallel)

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
        import subprocess  # noqa: F811  # nosec B404
        import sys
        from pathlib import Path as _Path
        _collector_err = _Path(effective_log_file).with_suffix(".collector.log")
        console.print(f"[bold cyan]Starting log collector[/] → {effective_log_file}")
        subprocess.Popen(  # nosec B603
            [sys.executable, "-m", "decnet.cli", "collect", "--log-file", str(effective_log_file)],
            stdin=subprocess.DEVNULL,
            stdout=open(_collector_err, "a"),  # nosec B603
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


@app.command()
def collect(
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to write RFC 5424 syslog lines and .json records"),
) -> None:
    """Stream Docker logs from all running decky service containers to a log file."""
    import asyncio
    from decnet.collector import log_collector_worker
    console.print(f"[bold cyan]Collector starting[/] → {log_file}")
    asyncio.run(log_collector_worker(log_file))


@app.command()
def mutate(
    watch: bool = typer.Option(False, "--watch", "-w", help="Run continuously and mutate deckies according to their interval"),
    decky_name: Optional[str] = typer.Option(None, "--decky", "-d", help="Force mutate a specific decky immediately"),
    force_all: bool = typer.Option(False, "--all", help="Force mutate all deckies immediately"),
) -> None:
    """Manually trigger or continuously watch for decky mutation."""
    from decnet.mutator import mutate_decky, mutate_all, run_watch_loop

    if watch:
        run_watch_loop()
        return

    if decky_name:
        mutate_decky(decky_name)
    elif force_all:
        mutate_all(force=True)
    else:
        mutate_all(force=False)


@app.command()
def status() -> None:
    """Show running deckies and their status."""
    from decnet.engine import status as _status
    _status()


@app.command()
def teardown(
    all_: bool = typer.Option(False, "--all", help="Tear down all deckies and remove network"),
    id_: Optional[str] = typer.Option(None, "--id", help="Tear down a specific decky by name"),
) -> None:
    """Stop and remove deckies."""
    if not all_ and not id_:
        console.print("[red]Specify --all or --id <name>.[/]")
        raise typer.Exit(1)

    from decnet.engine import teardown as _teardown
    _teardown(decky_id=id_)

    if all_:
        _kill_api()


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
) -> None:
    """Analyse logs for cross-decky traversals and print the attacker movement graph."""
    import sys
    import json as _json
    from pathlib import Path
    from decnet.correlation.engine import CorrelationEngine

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
) -> None:
    """Serve the DECNET Web Dashboard frontend."""
    import http.server
    import socketserver
    from pathlib import Path

    dist_dir = Path(__file__).parent.parent / "decnet_web" / "dist"

    if not dist_dir.exists():
        console.print(f"[red]Frontend build not found at {dist_dir}. Make sure you run 'npm run build' inside 'decnet_web'.[/]")
        raise typer.Exit(1)

    class SPAHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            path = self.translate_path(self.path)
            if not Path(path).exists() or Path(path).is_dir():
                self.path = "/index.html"
            return super().do_GET()

    import os
    os.chdir(dist_dir)

    with socketserver.TCPServer((host, web_port), SPAHTTPRequestHandler) as httpd:
        console.print(f"[green]Serving DECNET Web Dashboard on http://{host}:{web_port}[/]")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[dim]Shutting down dashboard server.[/]")

if __name__ == '__main__':  # pragma: no cover
    app()
