"""GET /topologies — paginated list of MazeNET topologies."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.db.models import TopologyListResponse, TopologySummary
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/",
    tags=["MazeNET Topologies"],
    response_model=TopologyListResponse,
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.topology.list")
async def api_list_topologies(
    status: Optional[str] = Query(default=None, description="Filter by topology status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _viewer: dict = Depends(require_viewer),
) -> TopologyListResponse:
    total = await repo.count_topologies(status=status)
    rows = await repo.list_topologies(status=status, limit=limit, offset=offset)
    return TopologyListResponse(
        total=total,
        limit=limit,
        offset=offset,
        data=[TopologySummary(**r) for r in rows],
    )
