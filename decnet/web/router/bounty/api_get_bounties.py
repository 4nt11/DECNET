from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import BountyResponse

router = APIRouter()


@router.get("/bounty", response_model=BountyResponse, tags=["Bounty Vault"],
    responses={401: {"description": "Could not validate credentials"}, 422: {"description": "Validation error"}},)
async def get_bounties(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    bounty_type: Optional[str] = None,
    search: Optional[str] = None,
    user: dict = Depends(require_viewer)
) -> dict[str, Any]:
    """Retrieve collected bounties (harvested credentials, payloads, etc.)."""
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    bt = _norm(bounty_type)
    s = _norm(search)

    _data = await repo.get_bounties(limit=limit, offset=offset, bounty_type=bt, search=s)
    _total = await repo.get_total_bounties(bounty_type=bt, search=s)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _data
    }
