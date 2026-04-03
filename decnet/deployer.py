"""
Deploy, teardown, and status via Docker SDK + subprocess docker compose.
"""

import subprocess
from pathlib import Path

import docker
from rich.console import Console
from rich.table import Table

from decnet.config import DecnetConfig, clear_state, load_state, save_state
from decnet.composer import write_compose
from decnet.network import (
    MACVLAN_NETWORK_NAME,
    allocate_ips,
    create_macvlan_network,
    detect_interface,
    detect_subnet,
    get_host_ip,
    ips_to_range,
    remove_macvlan_network,
    setup_host_macvlan,
    teardown_host_macvlan,
)

console = Console()
COMPOSE_FILE = Path("decnet-compose.yml")


def _compose(*args: str, compose_file: Path = COMPOSE_FILE) -> None:
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    subprocess.run(cmd, check=True)


def deploy(config: DecnetConfig, dry_run: bool = False, no_cache: bool = False) -> None:
    client = docker.from_env()

    # --- Network setup ---
    ip_list = [d.ip for d in config.deckies]
    decky_range = ips_to_range(ip_list)
    host_ip = get_host_ip(config.interface)

    console.print(f"[bold cyan]Creating MACVLAN network[/] ({MACVLAN_NETWORK_NAME}) on {config.interface}")
    if not dry_run:
        create_macvlan_network(
            client,
            interface=config.interface,
            subnet=config.subnet,
            gateway=config.gateway,
            ip_range=decky_range,
        )
        setup_host_macvlan(config.interface, host_ip, decky_range)

    # --- Compose generation ---
    compose_path = write_compose(config, COMPOSE_FILE)
    console.print(f"[bold cyan]Compose file written[/] → {compose_path}")

    if dry_run:
        console.print("[yellow]Dry run — no containers started.[/]")
        return

    # --- Save state before bring-up ---
    save_state(config, compose_path)

    # --- Bring up ---
    console.print("[bold cyan]Building images and starting deckies...[/]")
    if no_cache:
        _compose("build", "--no-cache", compose_file=compose_path)
    _compose("up", "--build", "-d", compose_file=compose_path)

    # --- Status summary ---
    _print_status(config)


def teardown(decky_id: str | None = None) -> None:
    state = load_state()
    if state is None:
        console.print("[red]No active deployment found (no decnet-state.json).[/]")
        return

    config, compose_path = state
    client = docker.from_env()

    if decky_id:
        # Bring down only the services matching this decky
        svc_names = [f"{decky_id}-{svc}" for svc in [d.services for d in config.deckies if d.name == decky_id]]
        if not svc_names:
            console.print(f"[red]Decky '{decky_id}' not found in current deployment.[/]")
            return
        _compose("stop", *svc_names, compose_file=compose_path)
        _compose("rm", "-f", *svc_names, compose_file=compose_path)
    else:
        _compose("down", compose_file=compose_path)

        ip_list = [d.ip for d in config.deckies]
        decky_range = ips_to_range(ip_list)
        teardown_host_macvlan(decky_range)
        remove_macvlan_network(client)
        clear_state()
        console.print("[green]All deckies torn down. MACVLAN network removed.[/]")


def status() -> None:
    state = load_state()
    if state is None:
        console.print("[yellow]No active deployment.[/]")
        return

    config, _ = state
    client = docker.from_env()

    table = Table(title="DECNET Deckies", show_lines=True)
    table.add_column("Decky", style="bold")
    table.add_column("IP")
    table.add_column("Services")
    table.add_column("Hostname")
    table.add_column("Status")

    running = {c.name: c.status for c in client.containers.list(all=True)}

    for decky in config.deckies:
        statuses = []
        for svc in decky.services:
            cname = f"{decky.name}-{svc}"
            st = running.get(cname, "absent")
            color = "green" if st == "running" else "red"
            statuses.append(f"[{color}]{svc}({st})[/{color}]")
        table.add_row(
            decky.name,
            decky.ip,
            " ".join(statuses),
            decky.hostname,
            "[green]up[/]" if all("running" in s for s in statuses) else "[red]degraded[/]",
        )

    console.print(table)


def _print_status(config: DecnetConfig) -> None:
    table = Table(title="Deployed Deckies", show_lines=True)
    table.add_column("Decky")
    table.add_column("IP")
    table.add_column("Services")
    for decky in config.deckies:
        table.add_row(decky.name, decky.ip, ", ".join(decky.services))
    console.print(table)
