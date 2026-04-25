"""
Deploy, teardown, and status via Docker SDK + subprocess docker compose.
"""

import asyncio
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

import anyio
import docker
from rich.console import Console
from rich.table import Table

from decnet.topology.hashing import canonical_hash

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
from decnet.topology.validate import (
    ValidationError,
    check_no_host_port_collision,
    errors as _validation_errors,
    validate as _validate_topology,
)

log = get_logger("engine")
console = Console()
COMPOSE_FILE = Path("decnet-compose.yml")
_CANONICAL_LOGGING = Path(__file__).parent.parent / "templates" / "syslog_bridge.py"
_CANONICAL_INSTANCE_SEED = Path(__file__).parent.parent / "templates" / "instance_seed.py"
_CANONICAL_SESSREC_DIR = Path(__file__).parent.parent / "templates" / "_shared" / "sessrec"
_SESSREC_SERVICES = {"ssh", "telnet"}
_CANONICAL_AUTH_HELPER_DIR = Path(__file__).parent.parent / "templates" / "_shared" / "auth-helper"
_AUTH_HELPER_SERVICES = {"ssh", "telnet"}
_CANONICAL_NTLMSSP = Path(__file__).parent.parent / "templates" / "_shared" / "ntlmssp.py"
_NTLMSSP_SERVICES = {"smb", "rdp"}


def _sync_logging_helper(config: DecnetConfig) -> None:
    """Copy canonical shared helpers into every active template build context."""
    from decnet.services.registry import get_service
    shared_files = [_CANONICAL_LOGGING, _CANONICAL_INSTANCE_SEED]
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
            for src in shared_files:
                dest = ctx / src.name
                if not dest.exists() or dest.read_bytes() != src.read_bytes():
                    shutil.copy2(src, dest)


def _sync_auth_helper_sources(config: DecnetConfig) -> None:
    """Copy auth-helper.c into SSH/Telnet build contexts as auth-helper/.

    The static cred-capture binary (compiled in a multi-stage Dockerfile
    layer via musl-gcc) is service-agnostic — same source compiles for
    both sshd's PAM stack (/etc/pam.d/sshd) and busybox-telnetd's
    /bin/login PAM stack (/etc/pam.d/login). Mirrors the sessrec sync
    pattern below.
    """
    from decnet.services.registry import get_service
    sources = [_CANONICAL_AUTH_HELPER_DIR / "auth-helper.c"]
    seen: set[Path] = set()
    for decky in config.deckies:
        for svc_name in decky.services:
            if svc_name not in _AUTH_HELPER_SERVICES:
                continue
            svc = get_service(svc_name)
            if svc is None:
                continue
            ctx = svc.dockerfile_context()
            if ctx is None or ctx in seen:
                continue
            seen.add(ctx)
            dest_dir = ctx / "auth-helper"
            dest_dir.mkdir(exist_ok=True)
            for src in sources:
                dest = dest_dir / src.name
                if not dest.exists() or dest.read_bytes() != src.read_bytes():
                    shutil.copy2(src, dest)


def _sync_ntlmssp_sources(config: DecnetConfig) -> None:
    """Copy _shared/ntlmssp.py into SMB/RDP build contexts.

    Both templates parse NTLMSSP Type 3 messages (SMB Session Setup,
    RDP NLA CredSSP); the canonical parser lives at
    ``templates/_shared/ntlmssp.py`` and is mirrored into each active
    build context here, mirroring the auth-helper / sessrec patterns.
    """
    from decnet.services.registry import get_service
    seen: set[Path] = set()
    for decky in config.deckies:
        for svc_name in decky.services:
            if svc_name not in _NTLMSSP_SERVICES:
                continue
            svc = get_service(svc_name)
            if svc is None:
                continue
            ctx = svc.dockerfile_context()
            if ctx is None or ctx in seen:
                continue
            seen.add(ctx)
            dest = ctx / _CANONICAL_NTLMSSP.name
            if not dest.exists() or dest.read_bytes() != _CANONICAL_NTLMSSP.read_bytes():
                shutil.copy2(_CANONICAL_NTLMSSP, dest)


def _sync_sessrec_sources(config: DecnetConfig) -> None:
    """Copy sessrec.c + Makefile into SSH/Telnet build contexts as sessrec/."""
    from decnet.services.registry import get_service
    sources = [
        _CANONICAL_SESSREC_DIR / "sessrec.c",
        _CANONICAL_SESSREC_DIR / "Makefile",
    ]
    seen: set[Path] = set()
    for decky in config.deckies:
        for svc_name in decky.services:
            if svc_name not in _SESSREC_SERVICES:
                continue
            svc = get_service(svc_name)
            if svc is None:
                continue
            ctx = svc.dockerfile_context()
            if ctx is None or ctx in seen:
                continue
            seen.add(ctx)
            dest_dir = ctx / "sessrec"
            dest_dir.mkdir(exist_ok=True)
            for src in sources:
                dest = dest_dir / src.name
                if not dest.exists() or dest.read_bytes() != src.read_bytes():
                    shutil.copy2(src, dest)


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

# Signature of a wedged buildx. The phrase is what buildx itself emits
# when its activity-file write fails. Pairing it with "read-only file
# system" avoids false-positives on stderr that merely mentions the
# activity dir path for unrelated reasons.
_BUILDX_WEDGE_SIGNATURE = "failed to update builder last activity time"
_BUILDX_EROFS_SIGNATURE = "read-only file system"

# Count above which we consider buildx's bind-mount table pathological.
# A healthy daemon has 0; a couple is transient during a build. Past
# 10 you're seeing accumulation from a previous failed run.
_BUILDKIT_MOUNT_THRESHOLD = 10


def _count_leaked_buildkit_mounts() -> int:
    """How many orphaned buildkit bind-mounts is the daemon holding?

    Best-effort: reads /proc/self/mounts and greps for the known
    buildkit tmp pattern. Returns 0 if the file can't be read so we
    never block a deploy over our own diagnostic.
    """
    try:
        with open("/proc/self/mounts", "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if "/var/lib/docker/tmp/buildkit-mount" in line)
    except OSError:
        return 0


def _format_subprocess_error(exc: BaseException) -> str:
    """Stringify CalledProcessError so stderr actually shows up.

    The default str(CalledProcessError) is just 'Command ... returned
    non-zero exit status N', which drops the stderr we carefully stuff
    our buildx recovery hint into. Status reasons and deploy-failure
    log lines were losing the payload — surface it here instead.
    """
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = (exc.stderr or "").strip()
        if stderr:
            return f"{exc}: {stderr}"
    return str(exc)


def _buildx_recovery_hint(*, leaked_mounts: int, original_stderr: str = "") -> str:
    """Compose a recovery recipe tailored to which side of the wedge fired.

    Three failure modes share the 'read-only file system' symptom:

    * **Sandboxed home** (path under ``/home/.../.docker``): the
      service unit has ``ProtectHome=read-only`` and docker CLI is
      trying to write its activity file in the user's HOME. Fix is
      to redirect ``DOCKER_CONFIG`` / ``BUILDX_CONFIG`` to a path
      inside ``ReadWritePaths``.

    * **Leaked mounts** (count > 0): buildkit accumulated bind mounts
      in /var/lib/docker/tmp from a prior failed build. Fix is to drop
      the mounts by stopping Docker, unmounting them explicitly, and
      starting clean — ``prune -af && systemctl restart`` alone does
      not evict already-held mounts.

    * **Driver corruption** (count == 0): the buildx driver's own
      state is inconsistent (activity dir permissions, stale instance
      pointer, etc.). Fix is to rebuild the default builder.
    """
    head = (
        "Buildx is wedged — Docker's build driver can no longer write "
        "its activity file (spurious 'read-only file system' error)."
    )

    # If the offending path is under /home/, leaked mounts are a red
    # herring — the unit's namespace is what's blocking the write.
    is_protecthome_case = (
        leaked_mounts == 0
        and "/home/" in original_stderr
        and ".docker/buildx" in original_stderr
    )
    if is_protecthome_case:
        fix = (
            "Path is under /home but no mounts are leaked — the API "
            "unit is running with ProtectHome=read-only and docker CLI "
            "can't write its activity file inside the user's HOME.\n"
            "Recovery (in the systemd unit):\n"
            "  Environment=DOCKER_CONFIG=<install_dir>/.docker\n"
            "  Environment=BUILDX_CONFIG=<install_dir>/.docker/buildx\n"
            "Then: sudo systemctl daemon-reload && sudo systemctl restart decnet-api\n"
            "(Already wired into deploy/decnet-api.service.j2 — re-run\n"
            "`decnet init` to refresh the installed unit, then restart.)"
        )
        tail = "See wiki: Troubleshooting → 'Buildx leaked mounts'."
        parts = [head, fix, tail]
        if original_stderr:
            parts.append(f"Original error:\n{original_stderr.strip()}")
        return "\n\n".join(parts)

    if leaked_mounts > 0:
        fix = (
            f"Detected {leaked_mounts} leaked buildkit bind-mounts — "
            "prune+restart alone won't evict them.\n"
            "Recovery:\n"
            "  1. sudo systemctl stop docker.socket docker.service\n"
            "  2. sudo pkill -9 -f buildkitd; sudo pkill -9 -f containerd-shim\n"
            "  3. for m in $(mount | awk '$3 ~ /buildkit-mount/ {print $3}'); do sudo umount -l \"$m\"; done\n"
            "  4. rm -rf ~/.docker/buildx/activity\n"
            "  5. sudo systemctl start docker\n"
            "  6. docker buildx use default   # bundled builder is reserved-named; switch to it"
        )
    else:
        fix = (
            "No leaked mounts (count=0) — the buildx driver state "
            "itself is inconsistent.\n"
            "Recovery:\n"
            "  1. rm -rf ~/.docker/buildx/activity ~/.docker/buildx/instances/*\n"
            "  2. docker buildx create --name decnet-builder --use --bootstrap\n"
            "     (the name 'default' is reserved by Docker — pick anything else)\n"
            "  3. docker buildx inspect"
        )
    tail = "See wiki: Troubleshooting → 'Buildx leaked mounts'."
    parts = [head, fix, tail]
    if original_stderr:
        parts.append(f"Original error:\n{original_stderr.strip()}")
    return "\n\n".join(parts)


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

    # Preflight: if buildx already looks wedged before the first attempt,
    # refuse to start — retrying just leaks more mounts. Only applies to
    # build-bearing invocations ("up --build", "build"); "down" etc. are
    # unaffected by buildx state.
    is_build_cmd = any(a in args for a in ("--build", "build"))
    if is_build_cmd:
        leaked = _count_leaked_buildkit_mounts()
        if leaked >= _BUILDKIT_MOUNT_THRESHOLD:
            hint = _buildx_recovery_hint(leaked_mounts=leaked)
            log.error("preflight: buildx wedge detected (%d mounts) — refusing to deploy", leaked)
            raise subprocess.CalledProcessError(
                returncode=1, cmd=cmd, output="", stderr=hint,
            )

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
        # Wedge match needs BOTH the buildx-specific phrase AND the
        # EROFS marker — otherwise unrelated stderr that mentions the
        # activity dir false-positives.
        if (
            _BUILDX_WEDGE_SIGNATURE in stderr_lower
            and _BUILDX_EROFS_SIGNATURE in stderr_lower
        ):
            leaked = _count_leaked_buildkit_mounts()
            hint = _buildx_recovery_hint(
                leaked_mounts=leaked,
                original_stderr=result.stderr or "",
            )
            console.print(f"[red]{hint}[/]")
            log.error("buildx wedge detected mid-build (%d mounts) — not retrying", leaked)
            raise subprocess.CalledProcessError(
                returncode=result.returncode, cmd=cmd,
                output=result.stdout, stderr=hint,
            )
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


def _emit_lifecycle_event(
    *,
    decky_name: str,
    old_services: list[str],
    new_services: list[str],
    trigger: str,
) -> None:
    """Fire a ``decky_mutated`` event from a sync code path.

    Deploy/teardown are sync functions; ``emit_decky_mutated`` is async
    because its bus half awaits.  Bus is ``None`` here (CLI has no live
    client), so only the syslog side actually does work — but running
    the coroutine keeps the emission site a single call regardless.
    Soft-fails: a missing log path or broken bus must not abort the
    deploy.  The import is lazy to dodge the circular dependency between
    ``decnet.mutator`` (which imports engine helpers) and this module.
    """
    try:
        from decnet.mutator.events import emit_decky_mutated
        asyncio.run(
            emit_decky_mutated(
                bus=None,
                decky=decky_name,
                old_services=old_services,
                new_services=new_services,
                trigger=trigger,  # type: ignore[arg-type]
            )
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("lifecycle event emission failed decky=%s trigger=%s: %s",
                    decky_name, trigger, exc)


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
    _sync_sessrec_sources(config)
    _sync_auth_helper_sources(config)
    _sync_ntlmssp_sources(config)

    compose_path = write_compose(config, COMPOSE_FILE)
    console.print(f"[bold cyan]Compose file written[/] → {compose_path}")

    if dry_run:
        log.info("deployment dry-run complete compose_path=%s", compose_path)
        console.print("[yellow]Dry run — no containers started.[/]")
        return

    save_state(config, compose_path)

    # Emit one creation event per decky so the correlation graph has a
    # well-formed lifecycle start (old_services=[] ⇒ new_services=<initial>).
    # Bus is None here — the syslog line is what the correlator consumes.
    for decky in config.deckies:
        _emit_lifecycle_event(
            decky_name=decky.name,
            old_services=[],
            new_services=list(decky.services),
            trigger="creation",
        )

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
        _emit_lifecycle_event(
            decky_name=decky.name,
            old_services=list(decky.services),
            new_services=[],
            trigger="retirement",
        )
        _compose("stop", *svc_names, compose_file=compose_path)
        _compose("rm", "-f", *svc_names, compose_file=compose_path)
    else:
        for decky in config.deckies:
            _emit_lifecycle_event(
                decky_name=decky.name,
                old_services=list(decky.services),
                new_services=[],
                trigger="retirement",
            )
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


async def _resolve_swarm_host(repo, host_uuid: str) -> dict:
    host = await repo.get_swarm_host_by_uuid(host_uuid)
    if host is None:
        raise ValueError(
            f"topology pinned to unknown swarm host {host_uuid!r}"
        )
    return host


async def _deploy_on_agent(repo, topology_id: str, hydrated: dict) -> None:
    """Route a topology apply to the agent pinned by ``target_host_uuid``.

    Local imports avoid a circular dependency: decnet.swarm.client already
    pulls decnet.engine indirectly via decnet.config.
    """
    from decnet.swarm.client import AgentClient

    target_host_uuid = hydrated["topology"]["target_host_uuid"]
    host = await _resolve_swarm_host(repo, target_host_uuid)
    version_hash = canonical_hash(hydrated)

    await transition_status(repo, topology_id, TopologyStatus.DEPLOYING)
    try:
        async with AgentClient(host=host) as agent:
            await agent.apply_topology(hydrated, version_hash)
    except Exception as exc:
        log.error(
            "topology %s agent-apply failed on %s: %s",
            topology_id, host.get("name"), exc,
        )
        await transition_status(
            repo, topology_id, TopologyStatus.FAILED,
            reason=_format_subprocess_error(exc),
        )
        raise

    await transition_status(repo, topology_id, TopologyStatus.ACTIVE)
    log.info(
        "topology %s deployed on agent %s (hash=%s)",
        topology_id, host.get("name"), version_hash[:12],
    )


async def resync_agent_topology(repo, topology_id: str) -> None:
    """Re-push an ACTIVE agent-targeted topology without status churn.

    Used by the mutator reconcile loop when an agent's reported
    applied_version_hash drifts from what master expects.  Unlike the
    initial deploy, we do NOT flip status — the topology is already
    ACTIVE; we just want the agent's cache + live state to match
    master's current hydrated blob.
    """
    from decnet.swarm.client import AgentClient

    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        raise ValueError(f"topology {topology_id!r} not found")
    target_host_uuid = hydrated["topology"].get("target_host_uuid")
    if not target_host_uuid:
        raise ValueError(
            f"topology {topology_id!r} has no target_host_uuid; "
            "resync is agent-only"
        )
    host = await _resolve_swarm_host(repo, target_host_uuid)
    version_hash = canonical_hash(hydrated)
    async with AgentClient(host=host) as agent:
        await agent.apply_topology(hydrated, version_hash)
    log.info(
        "topology %s resynced to agent %s (hash=%s)",
        topology_id, host.get("name"), version_hash[:12],
    )


async def _teardown_on_agent(repo, topology_id: str, hydrated: dict) -> None:
    """Route a topology teardown to the pinned agent."""
    from decnet.swarm.client import AgentClient

    target_host_uuid = hydrated["topology"]["target_host_uuid"]
    host = await _resolve_swarm_host(repo, target_host_uuid)

    await transition_status(repo, topology_id, TopologyStatus.TEARING_DOWN)
    try:
        async with AgentClient(host=host) as agent:
            await agent.teardown_topology(topology_id)
    except Exception as exc:
        log.warning(
            "topology %s agent-teardown failed on %s (continuing): %s",
            topology_id, host.get("name"), exc,
        )

    await transition_status(repo, topology_id, TopologyStatus.TORN_DOWN)
    log.info("topology %s torn down on agent %s", topology_id, host.get("name"))


def _warn_if_userland_proxy_enabled(hydrated: dict) -> None:
    """Soft warning: docker-proxy masks attacker source IPs.

    Only log if the topology will publish ports (gateway deckies with
    ``forwards_l3=True``) — no point scaring operators on port-less
    topologies.  Best-effort: any failure talking to the daemon is
    silently ignored.
    """
    publishes = any(
        (d.get("decky_config") or {}).get("forwards_l3")
        for d in hydrated.get("deckies", [])
    )
    if not publishes:
        return
    try:
        info = docker.from_env().info()
    except Exception:
        return
    if info.get("UserlandProxy") or info.get("Userland Proxy"):
        log.warning(
            "[USERLAND_PROXY] docker-proxy is enabled; attacker source IPs "
            "will appear as the bridge gateway. Set "
            '"userland-proxy": false in /etc/docker/daemon.json to preserve '
            "real source IPs."
        )


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

    # Precondition: validate before any status transition or Docker call.
    # Errors bubble up as ValidationError and leave status untouched.
    issues = _validate_topology(hydrated)
    if _validation_errors(issues):
        raise ValidationError(issues)

    lans = hydrated["lans"]
    compose_path = _topology_compose_path(topology_id)

    if dry_run:
        # Plan-only: don't touch repo status or Docker — write the compose
        # so operators can diff it, nothing else.
        write_topology_compose(hydrated, compose_path)
        console.print(
            f"[bold cyan]Dry run — topology compose file written[/] → {compose_path}"
        )
        log.info("topology %s dry-run complete", topology_id)
        return

    # Host-state precheck: PORT_COLLISION is a warning (docker-compose
    # will hard-fail if the port is actually unavailable; we just want
    # the clearer log line up-front).  Only runs at live deploy.
    for w in check_no_host_port_collision(hydrated):
        log.warning("[%s] %s", w.code, w.message)

    _warn_if_userland_proxy_enabled(hydrated)

    # Pinned to an agent?  Hand off to the mTLS path.  Everything below
    # this line is the master-local deploy.
    if hydrated["topology"].get("target_host_uuid"):
        await _deploy_on_agent(repo, topology_id, hydrated)
        return

    await transition_status(repo, topology_id, TopologyStatus.DEPLOYING)

    client = docker.from_env()
    created_networks: list[str] = []
    compose_started = False
    try:
        for lan in lans:
            net_name = _topology_network_name(topology_id, lan["name"])
            # DMZ LAN is publicly routable; internal LANs are isolated
            # from the host's default egress.
            internal = not lan["is_dmz"]
            create_bridge_network(
                client, net_name, lan["subnet"], internal=internal
            )
            created_networks.append(net_name)
        write_topology_compose(hydrated, compose_path)
        console.print(
            f"[bold cyan]Topology compose file written[/] → {compose_path}"
        )
        # Offload to a worker thread so the API event loop stays
        # responsive during the build — otherwise every other request
        # (mutator events, SSE, status polls) waits behind compose.
        await anyio.to_thread.run_sync(
            lambda: _compose_with_retry(
                "up", "--build", "-d", compose_file=compose_path,
            ),
        )
        compose_started = True
    except Exception as exc:
        log.error("topology %s deploy failed: %s", topology_id, exc)
        # Roll back any Docker state we created in this attempt so the
        # next deploy doesn't trip over orphan networks or half-started
        # containers. Best-effort: rollback errors must not mask the
        # original deploy failure.
        if compose_started or compose_path.exists():
            try:
                _compose(
                    "down", "--remove-orphans", compose_file=compose_path
                )
            except Exception as rb_exc:  # pragma: no cover
                log.warning(
                    "topology %s rollback compose-down failed: %s",
                    topology_id, rb_exc,
                )
        for net_name in reversed(created_networks):
            try:
                remove_bridge_network(client, net_name)
            except Exception as rb_exc:  # pragma: no cover
                log.warning(
                    "topology %s rollback network %s removal failed: %s",
                    topology_id, net_name, rb_exc,
                )
        if compose_path.exists():
            try:
                compose_path.unlink()
            except OSError:  # pragma: no cover
                pass
        await transition_status(
            repo, topology_id, TopologyStatus.FAILED,
            reason=_format_subprocess_error(exc),
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

    if hydrated["topology"].get("target_host_uuid"):
        await _teardown_on_agent(repo, topology_id, hydrated)
        return

    await transition_status(repo, topology_id, TopologyStatus.TEARING_DOWN)

    client = docker.from_env()
    compose_path = _topology_compose_path(topology_id)

    if compose_path.exists():
        try:
            await anyio.to_thread.run_sync(
                lambda: _compose(
                    "down", "--remove-orphans", compose_file=compose_path,
                ),
            )
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
