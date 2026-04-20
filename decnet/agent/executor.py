"""Thin adapter between the agent's HTTP endpoints and the existing
``decnet.engine.deployer`` code path.

Kept deliberately small: the agent does not re-implement deployment logic,
it only translates a master RPC into the same function calls the unihost
CLI already uses.  Everything runs in a worker thread (the deployer is
blocking) so the FastAPI event loop stays responsive.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Network
from typing import Any

from decnet.engine import deployer as _deployer
from decnet.config import DecnetConfig, load_state, clear_state
from decnet.logging import get_logger
from decnet.network import (
    allocate_ips,
    detect_interface,
    detect_subnet,
    get_host_ip,
)

log = get_logger("agent.executor")


def _relocalize(config: DecnetConfig) -> DecnetConfig:
    """Rewrite a master-built config to the worker's local network reality.

    The master populates ``interface``/``subnet``/``gateway`` from its own
    box before dispatching, which blows up the deployer on any worker whose
    NIC name differs (common in heterogeneous fleets — master on ``wlp6s0``,
    worker on ``enp0s3``). We always re-detect locally; if the worker sits
    on a different subnet than the master, decky IPs are re-allocated from
    the worker's subnet so they're actually reachable.
    """
    local_iface = detect_interface()
    local_subnet, local_gateway = detect_subnet(local_iface)
    local_host_ip = get_host_ip(local_iface)

    updates: dict[str, Any] = {
        "interface": local_iface,
        "subnet": local_subnet,
        "gateway": local_gateway,
    }

    master_net = IPv4Network(config.subnet, strict=False) if config.subnet else None
    local_net = IPv4Network(local_subnet, strict=False)
    if master_net is None or master_net != local_net:
        log.info(
            "agent.deploy subnet mismatch master=%s local=%s — re-allocating decky IPs",
            config.subnet, local_subnet,
        )
        fresh_ips = allocate_ips(
            subnet=local_subnet,
            gateway=local_gateway,
            host_ip=local_host_ip,
            count=len(config.deckies),
        )
        new_deckies = [d.model_copy(update={"ip": ip}) for d, ip in zip(config.deckies, fresh_ips)]
        updates["deckies"] = new_deckies

    return config.model_copy(update=updates)


async def deploy(config: DecnetConfig, dry_run: bool = False, no_cache: bool = False) -> None:
    """Run the blocking deployer off-loop. The deployer itself calls
    save_state() internally once the compose file is materialised."""
    log.info(
        "agent.deploy mode=%s deckies=%d interface=%s (incoming)",
        config.mode, len(config.deckies), config.interface,
    )
    if config.mode == "swarm":
        config = _relocalize(config)
        log.info(
            "agent.deploy relocalized interface=%s subnet=%s gateway=%s",
            config.interface, config.subnet, config.gateway,
        )
    await asyncio.to_thread(_deployer.deploy, config, dry_run, no_cache, False)


async def teardown(decky_id: str | None = None) -> None:
    log.info("agent.teardown decky_id=%s", decky_id)
    await asyncio.to_thread(_deployer.teardown, decky_id)
    if decky_id is None:
        await asyncio.to_thread(clear_state)


def _decky_runtime_states(config: DecnetConfig) -> dict[str, dict[str, Any]]:
    """Map decky_name → {"running": bool, "services": {svc: container_state}}.

    Queried so the master can tell, after a partial-failure deploy, which
    deckies actually came up instead of tainting the whole shard as failed.
    Best-effort: a docker error returns an empty map, not an exception.
    """
    try:
        import docker  # local import — agent-only path
        client = docker.from_env()
        live = {c.name: c.status for c in client.containers.list(all=True, ignore_removed=True)}
    except Exception:  # pragma: no cover — defensive
        log.exception("_decky_runtime_states: docker query failed")
        return {}

    out: dict[str, dict[str, Any]] = {}
    for d in config.deckies:
        svc_states = {
            svc: live.get(f"{d.name}-{svc.replace('_', '-')}", "absent")
            for svc in d.services
        }
        out[d.name] = {
            "running": bool(svc_states) and all(s == "running" for s in svc_states.values()),
            "services": svc_states,
        }
    return out


_REAPER_SCRIPT = r"""#!/bin/bash
# DECNET agent self-destruct reaper.
# Runs detached from the agent process so it survives the agent's death.
# Waits briefly for the HTTP response to drain, then stops services,
# wipes install paths, and preserves logs.
set +e

sleep 3

# Stop decky containers started by the local deployer (best-effort).
if command -v docker >/dev/null 2>&1; then
    docker ps -q --filter "label=com.docker.compose.project=decnet" | xargs -r docker stop
    docker ps -aq --filter "label=com.docker.compose.project=decnet" | xargs -r docker rm -f
    docker network rm decnet_lan 2>/dev/null
fi

# Stop+disable every systemd unit the installer may have dropped.
for unit in decnet-agent decnet-engine decnet-collector decnet-forwarder decnet-prober decnet-sniffer decnet-updater; do
    systemctl stop "$unit" 2>/dev/null
    systemctl disable "$unit" 2>/dev/null
done

# Nuke install paths. Logs under /var/log/decnet* are intentionally
# preserved — the operator typically wants them for forensic review.
rm -rf /opt/decnet* /var/lib/decnet/* /usr/local/bin/decnet* /etc/decnet
rm -f /etc/systemd/system/decnet-*.service /etc/systemd/system/decnet-*.timer

systemctl daemon-reload 2>/dev/null
rm -f "$0"
"""


async def self_destruct() -> None:
    """Tear down deckies, then spawn a detached reaper that wipes the
    install footprint. Returns immediately so the HTTP response can drain
    before the reaper starts deleting files out from under the agent."""
    import os
    import shutil
    import subprocess  # nosec B404
    import tempfile

    # Best-effort teardown first — the reaper also runs docker stop, but
    # going through the deployer gives the host-macvlan/ipvlan helper a
    # chance to clean up routes cleanly.
    try:
        await asyncio.to_thread(_deployer.teardown, None)
        await asyncio.to_thread(clear_state)
    except Exception:
        log.exception("self_destruct: pre-reap teardown failed — reaper will force-stop containers")

    # Reaper lives under /tmp so it survives rm -rf /opt/decnet*.
    fd, path = tempfile.mkstemp(prefix="decnet-reaper-", suffix=".sh", dir="/tmp")  # nosec B108 — reaper must outlive /opt/decnet removal
    try:
        os.write(fd, _REAPER_SCRIPT.encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o700)  # nosec B103 — root-owned reaper, needs exec

    # The reaper MUST run outside decnet-agent.service's cgroup — otherwise
    # `systemctl stop decnet-agent` SIGTERMs the whole cgroup (reaper included)
    # before rm -rf completes. `start_new_session=True` gets us a fresh POSIX
    # session but does NOT escape the systemd cgroup. So we prefer
    # `systemd-run --scope` (launches the command in a transient scope
    # detached from the caller's service), falling back to a bare Popen if
    # systemd-run is unavailable (non-systemd host / container).
    systemd_run = shutil.which("systemd-run")
    if systemd_run:
        argv = [
            systemd_run,
            "--collect",
            "--unit", f"decnet-reaper-{os.getpid()}",
            "--description", "DECNET agent self-destruct reaper",
            "/bin/bash", path,
        ]
        spawn_kwargs = {"start_new_session": True}
    else:
        argv = ["/bin/bash", path]
        spawn_kwargs = {"start_new_session": True}

    subprocess.Popen(  # nosec B603
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        **spawn_kwargs,
    )
    log.warning(
        "self_destruct: reaper spawned path=%s via=%s — agent will die in ~3s",
        path, "systemd-run" if systemd_run else "popen",
    )


async def status() -> dict[str, Any]:
    state = await asyncio.to_thread(load_state)
    if state is None:
        return {"deployed": False, "deckies": []}
    config, _compose_path = state
    runtime = await asyncio.to_thread(_decky_runtime_states, config)
    return {
        "deployed": True,
        "mode": config.mode,
        "compose_path": str(_compose_path),
        "deckies": [d.model_dump() for d in config.deckies],
        "runtime": runtime,
    }
