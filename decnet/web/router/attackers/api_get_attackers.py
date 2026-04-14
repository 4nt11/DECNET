from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import AttackersResponse

router = APIRouter()


@router.get(
    "/attackers",
    response_model=AttackersResponse,
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        422: {"description": "Validation error"},
    },
)
async def get_attackers(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    search: Optional[str] = None,
    sort_by: str = Query("recent", pattern="^(recent|active|traversals)$"),
    service: Optional[str] = None,
    current_user: str = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve paginated attacker profiles."""
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    s = _norm(search)
    svc = _norm(service)
    _data = await repo.get_attackers(limit=limit, offset=offset, search=s, sort_by=sort_by, service=svc)
    _total = await repo.get_total_attackers(search=s, service=svc)
    return {"total": _total, "limit": limit, "offset": offset, "data": _data}
