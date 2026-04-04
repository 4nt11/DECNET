"""
Deploy, teardown, and status via Docker SDK + subprocess docker compose.
"""

import subprocess
import time
from pathlib import Path

import docker
from rich.console import Console
from rich.table import Table

from decnet.config import DecnetConfig, clear_state, load_state, save_state
from decnet.composer import write_compose
from decnet.network import (
    MACVLAN_NETWORK_NAME,
    create_ipvlan_network,
    create_macvlan_network,
    get_host_ip,
    ips_to_range,
    remove_macvlan_network,
    setup_host_ipvlan,
    setup_host_macvlan,
    teardown_host_ipvlan,
    teardown_host_macvlan,
)

console = Console()
COMPOSE_FILE = Path("decnet-compose.yml")


def _compose(*args: str, compose_file: Path = COMPOSE_FILE) -> None:
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    subprocess.run(cmd, check=True)


_PERMANENT_ERRORS = (
    "manifest unknown",
    "manifest for",
    "not found",
    "pull access denied",
    "repository does not exist",
)


def _compose_with_retry(
    *args: str,
    compose_file: Path = COMPOSE_FILE,
    retries: int = 3,
    delay: float = 5.0,
) -> None:
    """Run a docker compose command, retrying on transient failures."""
    last_exc: subprocess.CalledProcessError | None = None
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    for attempt in range(1, retries + 1):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            if result.stdout:
                print(result.stdout, end="")
            return
        last_exc = subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )
        stderr_lower = (result.stderr or "").lower()
        if any(pat in stderr_lower for pat in _PERMANENT_ERRORS):
            console.print(f"[red]Permanent Docker error — not retrying:[/]\n{result.stderr.strip()}")
            raise last_exc
        if attempt < retries:
            console.print(
                f"[yellow]docker compose {' '.join(args)} failed "
                f"(attempt {attempt}/{retries}), retrying in {delay:.0f}s…[/]"
            )
            if result.stderr:
                console.print(f"[dim]{result.stderr.strip()}[/]")
            time.sleep(delay)
            delay *= 2
        else:
            if result.stderr:
                console.print(f"[red]{result.stderr.strip()}[/]")
    raise last_exc


def deploy(config: DecnetConfig, dry_run: bool = False, no_cache: bool = False) -> None:
    client = docker.from_env()

    # --- Network setup ---
    ip_list = [d.ip for d in config.deckies]
    decky_range = ips_to_range(ip_list)
    host_ip = get_host_ip(config.interface)

    net_driver = "IPvlan L2" if config.ipvlan else "MACVLAN"
    console.print(f"[bold cyan]Creating {net_driver} network[/] ({MACVLAN_NETWORK_NAME}) on {config.interface}")
    if not dry_run:
        if config.ipvlan:
            create_ipvlan_network(
                client,
                interface=config.interface,
                subnet=config.subnet,
                gateway=config.gateway,
                ip_range=decky_range,
            )
            setup_host_ipvlan(config.interface, host_ip, decky_range)
        else:
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
        _compose_with_retry("build", "--no-cache", compose_file=compose_path)
    _compose_with_retry("up", "--build", "-d", compose_file=compose_path)

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
        if config.ipvlan:
            teardown_host_ipvlan(decky_range)
        else:
            teardown_host_macvlan(decky_range)
        remove_macvlan_network(client)
        clear_state()
        net_driver = "IPvlan" if config.ipvlan else "MACVLAN"
        console.print(f"[green]All deckies torn down. {net_driver} network removed.[/]")


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
            cname = f"{decky.name}-{svc.replace('_', '-')}"
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
