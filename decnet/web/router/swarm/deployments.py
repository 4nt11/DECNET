"""Deployment dispatch: shard deckies across enrolled workers and push.

The master owns the DecnetConfig. Per worker we build a filtered copy
containing only the deckies assigned to that worker (via ``host_uuid``),
then POST it to the worker agent.  Sharding strategy is explicit: the
caller is expected to have already set ``host_uuid`` on every decky.  If
any decky arrives without one, we fail fast — auto-sharding lives in the
CLI layer (task #7), not here.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from decnet.config import DecnetConfig, DeckyConfig
from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo

log = get_logger("swarm.deployments")

router = APIRouter(tags=["swarm-deployments"])


class DeployRequest(BaseModel):
    config: DecnetConfig
    dry_run: bool = False
    no_cache: bool = False


class TeardownRequest(BaseModel):
    host_uuid: str | None = Field(
        default=None,
        description="If set, tear down only this worker; otherwise tear down all hosts",
    )
    decky_id: str | None = None


class HostResult(BaseModel):
    host_uuid: str
    host_name: str
    ok: bool
    detail: Any | None = None


class DeployResponse(BaseModel):
    results: list[HostResult]


# ----------------------------------------------------------------- helpers


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


def _worker_config(base: DecnetConfig, shard: list[DeckyConfig]) -> DecnetConfig:
    return base.model_copy(update={"deckies": shard})


# ------------------------------------------------------------------ routes


@router.post("/deploy", response_model=DeployResponse)
async def deploy(
    req: DeployRequest,
    repo: BaseRepository = Depends(get_repo),
) -> DeployResponse:
    if req.config.mode != "swarm":
        raise HTTPException(status_code=400, detail="mode must be 'swarm'")

    buckets = _shard_by_host(req.config)

    # Resolve host rows in one query-per-host pass; fail fast on unknown uuids.
    hosts: dict[str, dict[str, Any]] = {}
    for host_uuid in buckets:
        row = await repo.get_swarm_host_by_uuid(host_uuid)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown host_uuid: {host_uuid}")
        hosts[host_uuid] = row

    async def _dispatch(host_uuid: str, shard: list[DeckyConfig]) -> HostResult:
        host = hosts[host_uuid]
        cfg = _worker_config(req.config, shard)
        try:
            async with AgentClient(host=host) as agent:
                body = await agent.deploy(cfg, dry_run=req.dry_run, no_cache=req.no_cache)
            # Persist a DeckyShard row per decky for status lookups.
            for d in shard:
                await repo.upsert_decky_shard(
                    {
                        "decky_name": d.name,
                        "host_uuid": host_uuid,
                        "services": json.dumps(d.services),
                        "state": "running" if not req.dry_run else "pending",
                        "last_error": None,
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            await repo.update_swarm_host(host_uuid, {"status": "active"})
            return HostResult(host_uuid=host_uuid, host_name=host["name"], ok=True, detail=body)
        except Exception as exc:
            log.exception("swarm.deploy dispatch failed host=%s", host["name"])
            for d in shard:
                await repo.upsert_decky_shard(
                    {
                        "decky_name": d.name,
                        "host_uuid": host_uuid,
                        "services": json.dumps(d.services),
                        "state": "failed",
                        "last_error": str(exc)[:512],
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
            return HostResult(host_uuid=host_uuid, host_name=host["name"], ok=False, detail=str(exc))

    results = await asyncio.gather(
        *(_dispatch(uuid_, shard) for uuid_, shard in buckets.items())
    )
    return DeployResponse(results=list(results))


@router.post("/teardown", response_model=DeployResponse)
async def teardown(
    req: TeardownRequest,
    repo: BaseRepository = Depends(get_repo),
) -> DeployResponse:
    if req.host_uuid is not None:
        row = await repo.get_swarm_host_by_uuid(req.host_uuid)
        if row is None:
            raise HTTPException(status_code=404, detail="host not found")
        targets = [row]
    else:
        targets = await repo.list_swarm_hosts()

    async def _call(host: dict[str, Any]) -> HostResult:
        try:
            async with AgentClient(host=host) as agent:
                body = await agent.teardown(req.decky_id)
            if req.decky_id is None:
                await repo.delete_decky_shards_for_host(host["uuid"])
            return HostResult(host_uuid=host["uuid"], host_name=host["name"], ok=True, detail=body)
        except Exception as exc:
            log.exception("swarm.teardown failed host=%s", host["name"])
            return HostResult(
                host_uuid=host["uuid"], host_name=host["name"], ok=False, detail=str(exc)
            )

    results = await asyncio.gather(*(_call(h) for h in targets))
    return DeployResponse(results=list(results))
