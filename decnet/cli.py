"""
DECNET CLI — entry point for all commands.

Usage:
  decnet deploy --mode unihost --deckies 5 --randomize-services
  decnet status
  decnet teardown [--all | --id decky-01]
  decnet services
"""

import random
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
from decnet.distros import all_distros, get_distro, random_distro
from decnet.ini_loader import IniConfig, load_ini
from decnet.network import detect_interface, detect_subnet, allocate_ips, get_host_ip
from decnet.services.registry import all_services

app = typer.Typer(
    name="decnet",
    help="Deploy a deception network of honeypot deckies on your LAN.",
    no_args_is_help=True,
)
console = Console()

def _all_service_names() -> list[str]:
    """Return all registered service names from the live plugin registry."""
    return sorted(all_services().keys())


def _resolve_distros(
    distros_explicit: list[str] | None,
    randomize_distros: bool,
    n: int,
    archetype: Archetype | None = None,
) -> list[str]:
    """Return a list of n distro slugs based on CLI flags or archetype preference."""
    if distros_explicit:
        return [distros_explicit[i % len(distros_explicit)] for i in range(n)]
    if randomize_distros:
        return [random_distro().slug for _ in range(n)]
    if archetype:
        pool = archetype.preferred_distros
        return [pool[i % len(pool)] for i in range(n)]
    # Default: cycle through all distros to maximize heterogeneity
    slugs = list(all_distros().keys())
    return [slugs[i % len(slugs)] for i in range(n)]


def _build_deckies(
    n: int,
    ips: list[str],
    services_explicit: list[str] | None,
    randomize_services: bool,
    distros_explicit: list[str] | None = None,
    randomize_distros: bool = False,
    archetype: Archetype | None = None,
) -> list[DeckyConfig]:
    deckies = []
    used_combos: set[frozenset] = set()
    distro_slugs = _resolve_distros(distros_explicit, randomize_distros, n, archetype)

    for i, ip in enumerate(ips):
        name = f"decky-{i + 1:02d}"
        distro = get_distro(distro_slugs[i])
        hostname = random_hostname(distro.slug)

        if services_explicit:
            svc_list = services_explicit
        elif archetype:
            svc_list = list(archetype.services)
        elif randomize_services:
            svc_pool = _all_service_names()
            attempts = 0
            while True:
                count = random.randint(1, min(3, len(svc_pool)))
                chosen = frozenset(random.sample(svc_pool, count))
                attempts += 1
                if chosen not in used_combos or attempts > 20:
                    break
            svc_list = list(chosen)
            used_combos.add(chosen)
        else:
            typer.echo("Error: provide --services, --archetype, or --randomize-services.", err=True)
            raise typer.Exit(1)

        deckies.append(
            DeckyConfig(
                name=name,
                ip=ip,
                services=svc_list,
                distro=distro.slug,
                base_image=distro.image,
                build_base=distro.build_base,
                hostname=hostname,
                archetype=archetype.slug if archetype else None,
                nmap_os=archetype.nmap_os if archetype else "linux",
            )
        )
    return deckies


def _build_deckies_from_ini(
    ini: IniConfig,
    subnet_cidr: str,
    gateway: str,
    host_ip: str,
    randomize: bool,
    cli_mutate_interval: int | None = None,
) -> list[DeckyConfig]:
    """Build DeckyConfig list from an IniConfig, auto-allocating missing IPs."""
    from ipaddress import IPv4Address, IPv4Network
    import time
    now = time.time()

    explicit_ips: set[IPv4Address] = {
        IPv4Address(s.ip) for s in ini.deckies if s.ip
    }

    net = IPv4Network(subnet_cidr, strict=False)
    reserved = {
        net.network_address,
        net.broadcast_address,
        IPv4Address(gateway),
        IPv4Address(host_ip),
    } | explicit_ips

    auto_pool = (str(addr) for addr in net.hosts() if addr not in reserved)

    deckies: list[DeckyConfig] = []
    for spec in ini.deckies:
        # Resolve archetype (if any) — explicit services/distro override it
        arch: Archetype | None = None
        if spec.archetype:
            arch = get_archetype(spec.archetype)

        # Distro: archetype preferred list → random → global cycle
        distro_pool = arch.preferred_distros if arch else list(all_distros().keys())
        distro = get_distro(distro_pool[len(deckies) % len(distro_pool)])
        hostname = random_hostname(distro.slug)

        ip = spec.ip or next(auto_pool, None)
        if ip is None:
            raise ValueError(f"Not enough free IPs in {subnet_cidr} while assigning IP for '{spec.name}'.")

        if spec.services:
            known = set(_all_service_names())
            unknown = [s for s in spec.services if s not in known]
            if unknown:
                raise ValueError(
                    f"Unknown service(s) in [{spec.name}]: {unknown}. "
                    f"Available: {_all_service_names()}"
                )
            svc_list = spec.services
        elif arch:
            svc_list = list(arch.services)
        elif randomize:
            svc_pool = _all_service_names()
            count = random.randint(1, min(3, len(svc_pool)))
            svc_list = random.sample(svc_pool, count)
        else:
            raise ValueError(
                f"Decky '[{spec.name}]' has no services= in config. "
                "Add services=, archetype=, or use --randomize-services."
            )

        # nmap_os priority: explicit INI key > archetype default > "linux"
        resolved_nmap_os = spec.nmap_os or (arch.nmap_os if arch else "linux")
        
        # mutation interval priority: CLI > per-decky INI > global INI
        decky_mutate_interval = cli_mutate_interval
        if decky_mutate_interval is None:
            decky_mutate_interval = spec.mutate_interval if spec.mutate_interval is not None else ini.mutate_interval

        deckies.append(DeckyConfig(
            name=spec.name,
            ip=ip,
            services=svc_list,
            distro=distro.slug,
            base_image=distro.image,
            build_base=distro.build_base,
            hostname=hostname,
            archetype=arch.slug if arch else None,
            service_config=spec.service_config,
            nmap_os=resolved_nmap_os,
            mutate_interval=decky_mutate_interval,
            last_mutated=now,
        ))
    return deckies



@app.command()
def api(
    port: int = typer.Option(DECNET_API_PORT, "--port", help="Port for the backend API"),
    host: str = typer.Option(DECNET_API_HOST, "--host", help="Host IP for the backend API"),
    log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Path to the DECNET log file to monitor"),
) -> None:
    """Run the DECNET API and Web Dashboard in standalone mode."""
    import subprocess
    import sys
    import os

    console.print(f"[green]Starting DECNET API on {host}:{port}...[/]")
    _env: dict[str, str] = os.environ.copy()
    _env["DECNET_INGEST_LOG_FILE"] = str(log_file)
    try:
        subprocess.run(
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
    log_target: Optional[str] = typer.Option(None, "--log-target", help="Forward logs to ip:port (e.g. 192.168.1.5:5140)"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Write RFC 5424 syslog to this path inside containers (e.g. /var/log/decnet/decnet.log)"),
    archetype_name: Optional[str] = typer.Option(None, "--archetype", "-a", help="Machine archetype slug (e.g. linux-server, windows-workstation)"),
    mutate_interval: Optional[int] = typer.Option(30, "--mutate-interval", help="Automatically rotate services every N minutes"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate compose file without starting containers"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Force rebuild all images, ignoring Docker layer cache"),
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

        # CLI flags override INI values when explicitly provided
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

        # Register bring-your-own services from INI before validation
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

        effective_log_target = log_target or ini.log_target
        effective_log_file = log_file
        try:
            decky_configs = _build_deckies_from_ini(
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
            known = set(_all_service_names())
            unknown = [s for s in services_list if s not in known]
            if unknown:
                console.print(f"[red]Unknown service(s): {unknown}. Available: {_all_service_names()}[/]")
                raise typer.Exit(1)

        # Resolve archetype if provided
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
        decky_configs = _build_deckies(
            deckies, ips, services_list, randomize_services,
            distros_explicit=distros_list, randomize_distros=randomize_distros,
            archetype=arch, mutate_interval=mutate_interval,
        )
        effective_log_target = log_target
        effective_log_file = log_file

    # Handle automatic log file for API
    if api and not effective_log_file:
        effective_log_file = os.path.join(os.getcwd(), "decnet.log")
        console.print(f"[cyan]API mode enabled: defaulting log-file to {effective_log_file}[/]")

    config = DecnetConfig(
        mode=mode,
        interface=iface,
        subnet=subnet_cidr,
        gateway=effective_gateway,
        deckies=decky_configs,
        log_target=effective_log_target,
        log_file=effective_log_file,
        ipvlan=ipvlan,
        mutate_interval=mutate_interval,
    )

    if effective_log_target and not dry_run:
        from decnet.logging.forwarder import probe_log_target
        if not probe_log_target(effective_log_target):
            console.print(f"[yellow]Warning: log target {effective_log_target} is unreachable. "
                          "Logs will be lost if it stays down.[/]")

    from decnet.deployer import deploy as _deploy
    _deploy(config, dry_run=dry_run, no_cache=no_cache)
    
    if mutate_interval is not None and not dry_run:
        import subprocess
        import sys
        console.print(f"[green]Starting DECNET Mutator watcher in the background (interval: {mutate_interval}m)...[/]")
        try:
            subprocess.Popen(
                [sys.executable, "-m", "decnet.cli", "mutate", "--watch"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start mutator watcher.[/]")

    if api and not dry_run:
        import subprocess
        import sys
        console.print(f"[green]Starting DECNET API on port {api_port}...[/]")
        _env: dict[str, str] = os.environ.copy()
        _env["DECNET_INGEST_LOG_FILE"] = str(effective_log_file)
        try:
            subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "decnet.web.api:app", "--host", "0.0.0.0", "--port", str(api_port)],
                env=_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            console.print(f"[dim]API running at http://0.0.0.0:{api_port}[/]")
        except (FileNotFoundError, subprocess.SubprocessError):
            console.print("[red]Failed to start API. Ensure 'uvicorn' is installed in the current environment.[/]")


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
    from decnet.deployer import status as _status
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

    from decnet.deployer import teardown as _teardown
    _teardown(decky_id=id_)


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

    # Assuming decnet_web/dist is relative to the project root
    dist_dir = Path(__file__).parent.parent / "decnet_web" / "dist"

    if not dist_dir.exists():
        console.print(f"[red]Frontend build not found at {dist_dir}. Make sure you run 'npm run build' inside 'decnet_web'.[/]")
        raise typer.Exit(1)

    class SPAHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            # Try to serve the requested file
            path = self.translate_path(self.path)
            if not Path(path).exists() or Path(path).is_dir():
                # If not found or is a directory, serve index.html (for React Router)
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
