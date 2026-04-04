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
) -> list[str]:
    """Return a list of n distro slugs based on CLI flags."""
    if distros_explicit:
        # Round-robin the provided list to fill n slots
        return [distros_explicit[i % len(distros_explicit)] for i in range(n)]
    if randomize_distros:
        return [random_distro().slug for _ in range(n)]
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
) -> list[DeckyConfig]:
    deckies = []
    used_combos: set[frozenset] = set()
    distro_slugs = _resolve_distros(distros_explicit, randomize_distros, n)

    for i, ip in enumerate(ips):
        name = f"decky-{i + 1:02d}"
        distro = get_distro(distro_slugs[i])
        hostname = random_hostname(distro.slug)

        if services_explicit:
            svc_list = services_explicit
        elif randomize_services:
            # Pick 1-3 random services from the full registry, avoid exact duplicates
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
            typer.echo("Error: provide --services or --randomize-services.", err=True)
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
            )
        )
    return deckies


def _build_deckies_from_ini(
    ini: IniConfig,
    subnet_cidr: str,
    gateway: str,
    host_ip: str,
    randomize: bool,
) -> list[DeckyConfig]:
    """Build DeckyConfig list from an IniConfig, auto-allocating missing IPs."""
    from ipaddress import IPv4Address, IPv4Network

    explicit_ips: set[IPv4Address] = {
        IPv4Address(s.ip) for s in ini.deckies if s.ip
    }

    # Build an IP iterator that skips reserved + explicit addresses
    net = IPv4Network(subnet_cidr, strict=False)
    reserved = {
        net.network_address,
        net.broadcast_address,
        IPv4Address(gateway),
        IPv4Address(host_ip),
    } | explicit_ips

    auto_pool = (str(addr) for addr in net.hosts() if addr not in reserved)

    distro_slugs = _resolve_distros(None, randomize, len(ini.deckies))
    deckies: list[DeckyConfig] = []
    for i, spec in enumerate(ini.deckies):
        distro = get_distro(distro_slugs[i])
        hostname = random_hostname(distro.slug)

        ip = spec.ip or next(auto_pool, None)
        if ip is None:
            raise RuntimeError(
                f"Not enough free IPs in {subnet_cidr} while assigning IP for '{spec.name}'."
            )

        if spec.services:
            known = set(_all_service_names())
            unknown = [s for s in spec.services if s not in known]
            if unknown:
                console.print(
                    f"[red]Unknown service(s) in [{spec.name}]: {unknown}. "
                    f"Available: {_all_service_names()}[/]"
                )
                raise typer.Exit(1)
            svc_list = spec.services
        elif randomize:
            svc_pool = _all_service_names()
            count = random.randint(1, min(3, len(svc_pool)))
            svc_list = random.sample(svc_pool, count)
        else:
            console.print(
                f"[red]Decky '[{spec.name}]' has no services= in config. "
                "Add services= or use --randomize-services.[/]"
            )
            raise typer.Exit(1)

        deckies.append(DeckyConfig(
            name=spec.name,
            ip=ip,
            services=svc_list,
            distro=distro.slug,
            base_image=distro.image,
            build_base=distro.build_base,
            hostname=hostname,
        ))
    return deckies


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
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate compose file without starting containers"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Force rebuild all images, ignoring Docker layer cache"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to INI config file"),
) -> None:
    """Deploy deckies to the LAN."""
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

        effective_log_target = log_target or ini.log_target
        decky_configs = _build_deckies_from_ini(
            ini, subnet_cidr, effective_gateway, host_ip, randomize_services
        )
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

        if not services_list and not randomize_services:
            console.print("[red]Specify --services or --randomize-services.[/]")
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
        )
        effective_log_target = log_target

    config = DecnetConfig(
        mode=mode,
        interface=iface,
        subnet=subnet_cidr,
        gateway=effective_gateway,
        deckies=decky_configs,
        log_target=effective_log_target,
    )

    if effective_log_target and not dry_run:
        from decnet.logging.forwarder import probe_log_target
        if not probe_log_target(effective_log_target):
            console.print(f"[yellow]Warning: log target {effective_log_target} is unreachable. "
                          "Logs will be lost if it stays down.[/]")

    from decnet.deployer import deploy as _deploy
    _deploy(config, dry_run=dry_run, no_cache=no_cache)


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
