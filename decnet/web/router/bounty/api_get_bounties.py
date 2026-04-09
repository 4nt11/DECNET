from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import BountyResponse

router = APIRouter()


@router.get("/bounty", response_model=BountyResponse, tags=["Bounty Vault"])
async def get_bounties(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    bounty_type: Optional[str] = None,
    search: Optional[str] = None,
    current_user: str = Depends(get_current_user)
) -> dict[str, Any]:
    """Retrieve collected bounties (harvested credentials, payloads, etc.)."""
    _data = await repo.get_bounties(limit=limit, offset=offset, bounty_type=bounty_type, search=search)
    _total = await repo.get_total_bounties(bounty_type=bounty_type, search=search)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _data
    }
