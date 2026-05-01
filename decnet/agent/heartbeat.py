"""Agent → master liveness heartbeat loop.

Every ``INTERVAL_S`` seconds the worker posts ``executor.status()`` to
``POST <master>/swarm/heartbeat`` over mTLS. The master pins the
presented client cert's SHA-256 against the ``SwarmHost`` row for the
claimed ``host_uuid``; a match refreshes ``last_heartbeat`` + each
``DeckyShard``'s snapshot + runtime state.

Identity comes from ``/etc/decnet/decnet.ini`` (seeded by the enroll
bundle) — specifically ``DECNET_HOST_UUID`` and ``DECNET_MASTER_HOST``.
The worker's existing ``~/.decnet/agent/`` bundle (or
``/etc/decnet/agent/``) provides the mTLS client cert.

Started/stopped via the agent FastAPI app's lifespan. If identity
plumbing is missing (pre-enrollment dev runs) the loop logs at DEBUG and
declines to start — callers don't have to guard it.
"""
from __future__ import annotations

import asyncio
import pathlib
from typing import Optional

import httpx

from decnet.agent import executor as _exec
from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.swarm.log_forwarder import build_worker_ssl_context

log = get_logger("agent.heartbeat")

INTERVAL_S = 30.0
_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)

_task: Optional[asyncio.Task] = None


def _resolve_agent_dir() -> pathlib.Path:
    """Match the agent-dir resolution order used by the agent server:
    DECNET_AGENT_DIR env, else /etc/decnet/agent (production install),
    else ~/.decnet/agent (dev)."""
    import os
    env = os.environ.get("DECNET_AGENT_DIR")
    if env:
        return pathlib.Path(env)
    system = pathlib.Path("/etc/decnet/agent")
    if system.exists():
        return system
    return pki.DEFAULT_AGENT_DIR


async def _tick(client: httpx.AsyncClient, url: str, host_uuid: str, agent_version: str) -> None:
    snap = await _exec.status()
    body: dict = {
        "host_uuid": host_uuid,
        "agent_version": agent_version,
        "status": snap,
    }
    # Best-effort: fold in applied-topology snapshot. Failures must never
    # wedge the heartbeat loop — master will fall back to "no topology
    # reported" which triggers a resync if it expected one.
    try:
        from decnet.agent import topology_ops as _topo_ops
        from decnet.agent.topology_store import TopologyStore
        store = TopologyStore(_resolve_agent_dir() / "topology.db")
        try:
            body["topology"] = _topo_ops.state(store)
        finally:
            store.close()
    except Exception:
        log.debug("heartbeat: topology state unavailable", exc_info=True)

    resp = await client.post(url, json=body)
    # 403 / 404 are terminal-ish — we still keep looping because an
    # operator may re-enrol the host mid-session, but we log loudly so
    # prod ops can spot cert-pinning drift.
    if resp.status_code == 204:
        return
    log.warning(
        "heartbeat rejected status=%d body=%s",
        resp.status_code, resp.text[:200],
    )


async def _loop(url: str, host_uuid: str, agent_version: str, ssl_ctx) -> None:
    log.info("heartbeat loop starting url=%s host_uuid=%s interval=%ss",
             url, host_uuid, INTERVAL_S)
    async with httpx.AsyncClient(verify=ssl_ctx, timeout=_TIMEOUT) as client:
        while True:
            try:
                await _tick(client, url, host_uuid, agent_version)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("heartbeat tick failed — will retry in %ss", INTERVAL_S)
            await asyncio.sleep(INTERVAL_S)


def start() -> Optional[asyncio.Task]:
    """Kick off the background heartbeat task. No-op if identity is
    unconfigured (dev mode) — the caller doesn't need to check."""
    global _task
    from decnet.env import (
        DECNET_HOST_UUID,
        DECNET_MASTER_HOST,
        DECNET_SWARMCTL_PORT,
    )

    if _task is not None and not _task.done():
        return _task
    if not DECNET_HOST_UUID or not DECNET_MASTER_HOST:
        log.debug("heartbeat not starting — DECNET_HOST_UUID or DECNET_MASTER_HOST unset")
        return None

    agent_dir = _resolve_agent_dir()
    try:
        ssl_ctx = build_worker_ssl_context(agent_dir)
    except Exception:
        log.exception("heartbeat not starting — worker SSL context unavailable at %s", agent_dir)
        return None

    try:
        from decnet import __version__ as _v  # type: ignore[attr-defined]
        agent_version = _v
    except Exception:
        agent_version = "unknown"

    url = f"https://{DECNET_MASTER_HOST}:{DECNET_SWARMCTL_PORT}/swarm/heartbeat"
    _task = asyncio.create_task(
        _loop(url, DECNET_HOST_UUID, agent_version, ssl_ctx),
        name="agent-heartbeat",
    )
    return _task


async def stop() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except (asyncio.CancelledError, Exception):
        pass
    _task = None
