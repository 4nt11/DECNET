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
    create_bridge_network,
    create_ipvlan_network,
    create_macvlan_network,
    get_host_ip,
    ips_to_range,
    remove_bridge_network,
    remove_macvlan_network,
    setup_host_ipvlan,
    setup_host_macvlan,
    teardown_host_ipvlan,
    teardown_host_macvlan,
)
from decnet.topology.compose import (
    _network_name as _topology_network_name,
    write_topology_compose,
)
from decnet.topology.persistence import hydrate, transition_status
from decnet.topology.status import TopologyStatus

log = get_logger("engine")
console = Console()
COMPOSE_FILE = Path("decnet-compose.yml")
_CANONICAL_LOGGING = Path(__file__).parent.parent / "templates" / "syslog_bridge.py"


def _sync_logging_helper(config: DecnetConfig) -> None:
    """Copy the canonical syslog_bridge.py into every active template build context."""
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
            dest = ctx / "syslog_bridge.py"
            if not dest.exists() or dest.read_bytes() != _CANONICAL_LOGGING.read_bytes():
                shutil.copy2(_CANONICAL_LOGGING, dest)


def _compose(*args: str, compose_file: Path = COMPOSE_FILE, env: dict | None = None) -> None:
    import os
    # -p decnet pins the compose project name. Without it, docker compose
    # derives the project from basename($PWD); when a daemon (systemd) runs
    # with WorkingDirectory=/ that basename is empty and compose aborts with
    # "project name must not be empty".
    cmd = ["docker", "compose", "-p", "decnet", "-f", str(compose_file), *args]
    merged = {**os.environ, **(env or {})}
    result = subprocess.run(cmd, capture_output=True, text=True, env=merged)  # nosec B603
    if result.stdout:
        print(result.stdout, end="")
    if result.returncode != 0:
        # Docker emits the useful detail ("Address already in use", which IP,
        # which port) on stderr. Surface it to the structured log so the
        # agent's journal carries it — without this the upstream traceback
        # just shows the exit code.
        if result.stderr:
            log.error("docker compose %s failed: %s", " ".join(args), result.stderr.strip())
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )


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
    # -p decnet pins the compose project name. Without it, docker compose
    # derives the project from basename($PWD); when a daemon (systemd) runs
    # with WorkingDirectory=/ that basename is empty and compose aborts with
    # "project name must not be empty".
    cmd = ["docker", "compose", "-p", "decnet", "-f", str(compose_file), *args]
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
                log.error("docker compose %s failed after %d attempts: %s",
                          " ".join(args), retries, result.stderr.strip())
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

    # Pre-up cleanup: a prior half-failed `up` can leave containers still
    # holding the IPs/ports this run wants, which surfaces as the recurring
    # "Address already in use" from Docker's IPAM. Best-effort — ignore
    # failure (e.g. nothing to tear down on a clean host).
    try:
        _compose("down", "--remove-orphans", compose_file=compose_path)
    except subprocess.CalledProcessError:
        log.debug("pre-up cleanup: compose down failed (likely nothing to remove)")

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
        decky = next((d for d in config.deckies if d.name == decky_id), None)
        if decky is None:
            console.print(f"[red]Decky '{decky_id}' not found in current deployment.[/]")
            return
        svc_names = [f"{decky_id}-{svc}" for svc in decky.services]
        if not svc_names:
            log.warning("teardown: decky %s has no services to stop", decky_id)
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


def _teardown_order(lans: list[dict]) -> list[str]:
    """Return LAN names in leaf-first (DMZ-last) teardown order.

    The generator names LANs in BFS order (``LAN-00`` = DMZ root,
    then children, then grandchildren), so reverse-name order is a
    correct leaf-first topological sort for the tree.  Cross-edges
    are membership-only — they don't introduce parent/child
    relationships, so the BFS numbering remains valid.
    """
    return sorted((lan["name"] for lan in lans), reverse=True)


def _topology_compose_path(topology_id: str) -> Path:
    return Path(f"decnet-topology-{topology_id[:8]}-compose.yml")


@_traced("engine.deploy_topology")
async def deploy_topology(repo, topology_id: str, *, dry_run: bool = False) -> None:
    """Deploy a persisted MazeNET topology.

    Assumes ``repo`` has the topology in ``pending`` state.  Creates one
    Docker bridge network per LAN, writes a per-topology compose file,
    and brings all deckies up.  Marks ``active`` on success, ``failed``
    on exception (partial state left for later teardown).
    """
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        raise ValueError(f"topology {topology_id!r} not found")

    await transition_status(repo, topology_id, TopologyStatus.DEPLOYING)

    client = docker.from_env()
    lans = hydrated["lans"]
    compose_path = _topology_compose_path(topology_id)

    try:
        for lan in lans:
            net_name = _topology_network_name(topology_id, lan["name"])
            # DMZ LAN is publicly routable; internal LANs are isolated
            # from the host's default egress.
            internal = not lan["is_dmz"]
            create_bridge_network(
                client, net_name, lan["subnet"], internal=internal
            )
        write_topology_compose(hydrated, compose_path)
        console.print(
            f"[bold cyan]Topology compose file written[/] → {compose_path}"
        )
        if dry_run:
            log.info("topology %s dry-run complete", topology_id)
            return
        _compose_with_retry("up", "--build", "-d", compose_file=compose_path)
    except Exception as exc:
        log.error("topology %s deploy failed: %s", topology_id, exc)
        await transition_status(
            repo, topology_id, TopologyStatus.FAILED, reason=str(exc)
        )
        raise

    await transition_status(repo, topology_id, TopologyStatus.ACTIVE)
    log.info("topology %s deployed n_lans=%d", topology_id, len(lans))


@_traced("engine.teardown_topology")
async def teardown_topology(repo, topology_id: str) -> None:
    """Tear down a persisted MazeNET topology.

    Legal from ``active|degraded|failed|deploying``.  Brings compose
    down, removes each LAN's Docker bridge network in leaf-first order,
    and marks ``torn_down``.
    """
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        raise ValueError(f"topology {topology_id!r} not found")

    await transition_status(repo, topology_id, TopologyStatus.TEARING_DOWN)

    client = docker.from_env()
    compose_path = _topology_compose_path(topology_id)

    if compose_path.exists():
        try:
            _compose("down", "--remove-orphans", compose_file=compose_path)
        except subprocess.CalledProcessError as exc:
            log.warning(
                "topology %s compose down failed (continuing): %s",
                topology_id, exc,
            )

    for lan_name in _teardown_order(hydrated["lans"]):
        net_name = _topology_network_name(topology_id, lan_name)
        remove_bridge_network(client, net_name)

    if compose_path.exists():
        compose_path.unlink()

    await transition_status(repo, topology_id, TopologyStatus.TORN_DOWN)
    log.info("topology %s torn down", topology_id)


def _print_status(config: DecnetConfig) -> None:
    table = Table(title="Deployed Deckies", show_lines=True)
    table.add_column("Decky")
    table.add_column("IP")
    table.add_column("Services")
    for decky in config.deckies:
        table.add_row(decky.name, decky.ip, ", ".join(decky.services))
    console.print(table)
