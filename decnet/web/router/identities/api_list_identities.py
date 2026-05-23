# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/identities — paginated list of resolved identities.

Returns an empty list while the clusterer hasn't run yet (the
identities table ships empty in the schema-only PR). See
development/IDENTITY_RESOLUTION.md.
"""
from typing import Any

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/identities",
    tags=["Identity Resolution"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.list_identities")
async def list_identities(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Paginated identity list, newest-updated first."""
    data = await repo.list_identities(limit=limit, offset=offset)
    total = await repo.count_identities()
    return {"total": total, "limit": limit, "offset": offset, "data": data}
