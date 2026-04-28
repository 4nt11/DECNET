"""POST /swarm/teardown — tear down one or all enrolled workers."""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo
from decnet.web.db.models import (
    SwarmDeployResponse,
    SwarmHostResult,
    SwarmTeardownRequest,
)

log = get_logger("swarm.teardown")

router = APIRouter()


@router.post(
    "/teardown",
    response_model=SwarmDeployResponse,
    tags=["Swarm Deployments"],
    responses={
        400: {"description": "Bad Request (malformed JSON body)"},
        404: {"description": "A targeted host does not exist"},
        422: {"description": "Request body validation error"},
    },
)
async def api_teardown_swarm(
    req: SwarmTeardownRequest,
    repo: BaseRepository = Depends(get_repo),
) -> SwarmDeployResponse:
    if req.host_uuid is not None:
        row = await repo.get_swarm_host_by_uuid(req.host_uuid)
        if row is None:
            raise HTTPException(status_code=404, detail="host not found")
        targets = [row]
    else:
        targets = await repo.list_swarm_hosts()

    async def _call(host: dict[str, Any]) -> SwarmHostResult:
        try:
            async with AgentClient(host=host) as agent:
                body = await agent.teardown(req.decky_id)
            if req.decky_id is None:
                await repo.delete_decky_shards_for_host(host["uuid"])
            return SwarmHostResult(host_uuid=host["uuid"], host_name=host["name"], ok=True, detail=body)
        except Exception as exc:
            log.exception("swarm.teardown failed host=%s", host["name"])
            return SwarmHostResult(
                host_uuid=host["uuid"], host_name=host["name"], ok=False, detail=str(exc)
            )

    results = await asyncio.gather(*(_call(h) for h in targets))
    return SwarmDeployResponse(results=list(results))
