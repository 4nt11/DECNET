"""GET /swarm/hosts/{uuid} — fetch a single worker by UUID."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo
from decnet.web.router.swarm._schemas import SwarmHostView

router = APIRouter()


@router.get("/hosts/{uuid}", response_model=SwarmHostView, tags=["Swarm Hosts"])
async def api_get_host(
    uuid: str,
    repo: BaseRepository = Depends(get_repo),
) -> SwarmHostView:
    row = await repo.get_swarm_host_by_uuid(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="host not found")
    return SwarmHostView(**row)
