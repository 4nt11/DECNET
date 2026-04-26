"""GET /api/v1/orchestrator/events — paginated orchestrator activity.

Mirrors :mod:`decnet.web.router.campaigns.api_list_campaigns`. The
orchestrator worker is the sole writer; this surface is read-only.
"""
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/orchestrator/events",
    tags=["Orchestrator"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.list_orchestrator_events")
async def list_orchestrator_events(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    kind: Optional[str] = Query(None, pattern="^(traffic|file)$"),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Paginated orchestrator-event list, newest first."""
    data = await repo.list_orchestrator_events(
        limit=limit, offset=offset, kind=kind,
    )
    total = await repo.count_orchestrator_events(kind=kind)
    return {"total": total, "limit": limit, "offset": offset, "data": data}
