from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import require_viewer, repo
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
    user: dict = Depends(require_viewer),
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

    # Bulk-join behavior rows for the IPs in this page to avoid N+1 queries.
    _ips = {row["ip"] for row in _data if row.get("ip")}
    _behaviors = await repo.get_behaviors_for_ips(_ips) if _ips else {}
    for row in _data:
        row["behavior"] = _behaviors.get(row.get("ip"))

    return {"total": _total, "limit": limit, "offset": offset, "data": _data}
