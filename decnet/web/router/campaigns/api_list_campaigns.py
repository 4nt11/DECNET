# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/campaigns — paginated list of campaigns.

Mirror of :mod:`decnet.web.router.identities.api_list_identities` for
the campaign layer. Returns an empty list while the campaign clusterer
hasn't run yet (the campaigns table ships empty).
"""
from typing import Any

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/campaigns",
    tags=["Campaign Clustering"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.list_campaigns")
async def list_campaigns(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Paginated campaign list, newest-updated first."""
    data = await repo.list_campaigns(limit=limit, offset=offset)
    total = await repo.count_campaigns()
    return {"total": total, "limit": limit, "offset": offset, "data": data}
