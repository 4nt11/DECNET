from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import LogsResponse

router = APIRouter()


@router.get("/logs", response_model=LogsResponse, tags=["Logs"],
    responses={401: {"description": "Could not validate credentials"}, 403: {"description": "Insufficient permissions"}, 422: {"description": "Validation error"}})
@_traced("api.get_logs")
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    search: Optional[str] = Query(None, max_length=512),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    user: dict = Depends(require_viewer)
) -> dict[str, Any]:
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    s = _norm(search)
    st = _norm(start_time)
    et = _norm(end_time)

    _logs: list[dict[str, Any]] = await repo.get_logs(limit=limit, offset=offset, search=s, start_time=st, end_time=et)
    _total: int = await repo.get_total_logs(search=s, start_time=st, end_time=et)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _logs
    }
