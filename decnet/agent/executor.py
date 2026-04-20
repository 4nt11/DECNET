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
