from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import LogsResponse

router = APIRouter()

_DATETIME_RE = r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$"


@router.get("/logs", response_model=LogsResponse, tags=["Logs"])
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None, max_length=512),
    start_time: Optional[str] = Query(None, pattern=_DATETIME_RE),
    end_time: Optional[str] = Query(None, pattern=_DATETIME_RE),
    current_user: str = Depends(get_current_user)
) -> dict[str, Any]:
    _logs: list[dict[str, Any]] = await repo.get_logs(limit=limit, offset=offset, search=search, start_time=start_time, end_time=end_time)
    _total: int = await repo.get_total_logs(search=search, start_time=start_time, end_time=end_time)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _logs
    }
