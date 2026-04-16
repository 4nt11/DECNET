"""
Deploy, teardown, and status via Docker SDK + subprocess docker compose.
"""

import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

import docker
from rich.console import Console
from rich.table import Table

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
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

log = get_logger("engine")
console = Console()
COMPOSE_FILE = Path("decnet-compose.yml")
_CANONICAL_LOGGING = Path(__file__).parent.parent.parent / "templates" / "decnet_logging.py"


def _sync_logging_helper(config: DecnetConfig) -> None:
    """Copy the canonical decnet_logging.py into every active template build context."""
    from decnet.services.registry import get_service
    seen: set[Path] = set()
    for decky in config.deckies:
        for svc_name in decky.services:
            svc = get_service(svc_name)
            if svc is None:
                continue
            ctx = svc.dockerfile_context()
            if ctx is None or ctx in seen:
                continue
            seen.add(ctx)
            dest = ctx / "decnet_logging.py"
            if not dest.exists() or dest.read_bytes() != _CANONICAL_LOGGING.read_bytes():
                shutil.copy2(_CANONICAL_LOGGING, dest)


def _compose(*args: str, compose_file: Path = COMPOSE_FILE, env: dict | None = None) -> None:
    import os
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    merged = {**os.environ, **(env or {})}
    subprocess.run(cmd, check=True, env=merged)  # nosec B603


_PERMANENT_ERRORS = (
    "manifest unknown",
    "manifest for",
    "not found",
    "pull access denied",
    "repository does not exist",
)


@_traced("engine.compose_with_retry")
def _compose_with_retry(
    *args: str,
    compose_file: Path = COMPOSE_FILE,
    retries: int = 3,
    delay: float = 5.0,
    env: dict | None = None,
) -> None:
    """Run a docker compose command, retrying on transient failures."""
    import os
    last_exc: subprocess.CalledProcessError | None = None
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    merged = {**os.environ, **(env or {})}
    for attempt in range(1, retries + 1):
        result = subprocess.run(cmd, capture_output=True, text=True, env=merged)  # nosec B603
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


@_traced("engine.deploy")
def deploy(config: DecnetConfig, dry_run: bool = False, no_cache: bool = False, parallel: bool = False) -> None:
    log.info("deployment started n_deckies=%d interface=%s subnet=%s dry_run=%s", len(config.deckies), config.interface, config.subnet, dry_run)
    log.debug("deploy: deckies=%s", [d.name for d in config.deckies])
    client = docker.from_env()

    ip_list = [d.ip for d in config.deckies]
    decky_range = ips_to_range(ip_list)
    host_ip = get_host_ip(config.interface)
    log.debug("deploy: ip_range=%s host_ip=%s", decky_range, host_ip)

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

    _sync_logging_helper(config)

    compose_path = write_compose(config, COMPOSE_FILE)
    console.print(f"[bold cyan]Compose file written[/] → {compose_path}")

    if dry_run:
        log.info("deployment dry-run complete compose_path=%s", compose_path)
        console.print("[yellow]Dry run — no containers started.[/]")
        return

    save_state(config, compose_path)

    build_env = {"DOCKER_BUILDKIT": "1"} if parallel else {}

    console.print("[bold cyan]Building images and starting deckies...[/]")
    build_args = ["build"]
    if no_cache:
        build_args.append("--no-cache")

    if parallel:
        console.print("[bold cyan]Parallel build enabled — building all images concurrently...[/]")
        _compose_with_retry(*build_args, compose_file=compose_path, env=build_env)
        _compose_with_retry("up", "-d", compose_file=compose_path, env=build_env)
    else:
        if no_cache:
            _compose_with_retry("build", "--no-cache", compose_file=compose_path)
        _compose_with_retry("up", "--build", "-d", compose_file=compose_path)

    log.info("deployment complete n_deckies=%d", len(config.deckies))
    _print_status(config)


@_traced("engine.teardown")
def teardown(decky_id: str | None = None) -> None:
    log.info("teardown requested decky_id=%s", decky_id or "all")
    state = load_state()
    if state is None:
        log.warning("teardown: no active deployment found")
        console.print("[red]No active deployment found (no decnet-state.json).[/]")
        return

    config, compose_path = state
    client = docker.from_env()

    if decky_id:
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
        log.info("teardown complete all deckies removed network_driver=%s", net_driver)
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

    running = {c.name: c.status for c in client.containers.list(all=True, ignore_removed=True)}

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
