"""GET /swarm/hosts — admin-gated list of enrolled workers for the dashboard.

Thin wrapper over ``repo.list_swarm_hosts()`` — same shape as the
unauth'd controller route, but behind ``require_admin``.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from decnet.web.db.models import SwarmHostView
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

router = APIRouter()


@router.get("/hosts", response_model=list[SwarmHostView], tags=["Swarm Management"])
async def list_hosts(
    host_status: Optional[str] = None,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> list[SwarmHostView]:
    rows = await repo.list_swarm_hosts(host_status)
    return [SwarmHostView(**r) for r in rows]
