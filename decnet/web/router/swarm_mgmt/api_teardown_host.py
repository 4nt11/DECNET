"""POST /swarm/hosts/{uuid}/teardown — remote teardown on a swarm worker.

Body: ``{"decky_id": "..."}`` (optional). When ``decky_id`` is null/omitted
the agent tears down the entire host (all deckies + network); otherwise it
tears down that single decky. Mirrors the arguments of the local
``decnet teardown`` CLI command.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm.teardown")
router = APIRouter()


class TeardownHostRequest(BaseModel):
    decky_id: Optional[str] = None


class TeardownHostResponse(BaseModel):
    host_uuid: str
    host_name: str
    decky_id: Optional[str] = None
    ok: bool
    detail: str


@router.post(
    "/hosts/{uuid}/teardown",
    response_model=TeardownHostResponse,
    tags=["Swarm Management"],
)
async def teardown_host(
    uuid: str,
    req: TeardownHostRequest,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> TeardownHostResponse:
    host = await repo.get_swarm_host_by_uuid(uuid)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")

    try:
        async with AgentClient(host=host) as agent:
            body = await agent.teardown(req.decky_id)
    except Exception as exc:
        log.exception("swarm.teardown dispatch failed host=%s decky=%s",
                      host.get("name"), req.decky_id)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if req.decky_id:
        await repo.delete_decky_shard(req.decky_id)
    else:
        await repo.delete_decky_shards_for_host(uuid)

    return TeardownHostResponse(
        host_uuid=uuid,
        host_name=host.get("name") or "",
        decky_id=req.decky_id,
        ok=True,
        detail=str(body),
    )
