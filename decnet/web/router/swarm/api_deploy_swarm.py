"""POST /swarm/deploy — shard a DecnetConfig across enrolled workers.

Per worker we build a filtered copy containing only the deckies assigned
to that worker (via ``host_uuid``), then POST it to the worker agent.
The caller is expected to have already set ``host_uuid`` on every decky;
if any decky arrives without one, we fail fast. Auto-sharding lives in
the CLI layer, not here.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.config import DecnetConfig, DeckyConfig
from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo
from decnet.web.db.models import (
    SwarmDeployRequest,
    SwarmDeployResponse,
    SwarmHostResult,
)

log = get_logger("swarm.deploy")

router = APIRouter()


def _shard_by_host(config: DecnetConfig) -> dict[str, list[DeckyConfig]]:
    buckets: dict[str, list[DeckyConfig]] = {}
    for d in config.deckies:
        if not d.host_uuid:
            raise HTTPException(
                status_code=400,
                detail=f"decky '{d.name}' has no host_uuid — caller must shard before dispatch",
            )
        buckets.setdefault(d.host_uuid, []).append(d)
    return buckets


def _worker_config(
    base: DecnetConfig,
    shard: list[DeckyConfig],
    host: dict[str, Any],
) -> DecnetConfig:
    updates: dict[str, Any] = {"deckies": shard}
    # Per-host driver opt-in (Wi-Fi-bridged VMs can't use macvlan — see
    # SwarmHost.use_ipvlan). Never downgrade: if the operator picked ipvlan
    # at the deploy level, keep it regardless of the per-host flag.
    if host.get("use_ipvlan"):
        updates["ipvlan"] = True
    return base.model_copy(update=updates)


async def dispatch_decnet_config(
    config: DecnetConfig,
    repo: BaseRepository,
    dry_run: bool = False,
    no_cache: bool = False,
) -> SwarmDeployResponse:
    """Shard ``config`` by ``host_uuid`` and dispatch to each worker in parallel.

    Shared between POST /swarm/deploy (explicit swarm call) and the auto-swarm
    branch of POST /deckies/deploy.
    """
    buckets = _shard_by_host(config)

    hosts: dict[str, dict[str, Any]] = {}
    for host_uuid in buckets:
        row = await repo.get_swarm_host_by_uuid(host_uuid)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown host_uuid: {host_uuid}")
        hosts[host_uuid] = row

    async def _dispatch(host_uuid: str, shard: list[DeckyConfig]) -> SwarmHostResult:
        host = hosts[host_uuid]
        cfg = _worker_config(config, shard, host)
        try:
            async with AgentClient(host=host) as agent:
                body = await agent.deploy(cfg, dry_run=dry_run, no_cache=no_cache)
            for d in shard:
                await repo.upsert_decky_shard(
                    {
                        "decky_name": d.name,
                        "host_uuid": host_uuid,
                        "services": json.dumps(d.services),
                        "decky_config": d.model_dump_json(),
                        "decky_ip": d.ip,
                        "state": "running" if not dry_run else "pending",
                        "last_error": None,
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            await repo.update_swarm_host(host_uuid, {"status": "active"})
            return SwarmHostResult(host_uuid=host_uuid, host_name=host["name"], ok=True, detail=body)
        except Exception as exc:
            log.exception("swarm.deploy dispatch failed host=%s", host["name"])
            # Compose-up is partial-success-friendly: one decky failing to
            # build doesn't roll back the ones that already came up. Ask the
            # agent which containers actually exist before painting the whole
            # shard red — otherwise decky1 and decky2 look "failed" even
            # though they're live on the worker.
            runtime: dict[str, Any] = {}
            try:
                async with AgentClient(host=host) as probe:
                    snap = await probe.status()
                runtime = snap.get("runtime") or {}
            except Exception:
                log.warning("swarm.deploy: runtime probe failed host=%s — marking shard failed", host["name"])
            for d in shard:
                rstate = runtime.get(d.name) or {}
                is_up = bool(rstate.get("running"))
                await repo.upsert_decky_shard(
                    {
                        "decky_name": d.name,
                        "host_uuid": host_uuid,
                        "services": json.dumps(d.services),
                        "decky_config": d.model_dump_json(),
                        "decky_ip": d.ip,
                        "state": "running" if is_up else "failed",
                        "last_error": None if is_up else str(exc)[:512],
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            return SwarmHostResult(host_uuid=host_uuid, host_name=host["name"], ok=False, detail=str(exc))

    results = await asyncio.gather(
        *(_dispatch(uuid_, shard) for uuid_, shard in buckets.items())
    )
    return SwarmDeployResponse(results=list(results))


@router.post("/deploy", response_model=SwarmDeployResponse, tags=["Swarm Deployments"])
async def api_deploy_swarm(
    req: SwarmDeployRequest,
    repo: BaseRepository = Depends(get_repo),
) -> SwarmDeployResponse:
    if req.config.mode != "swarm":
        raise HTTPException(status_code=400, detail="mode must be 'swarm'")
    return await dispatch_decnet_config(
        req.config, repo, dry_run=req.dry_run, no_cache=req.no_cache
    )
