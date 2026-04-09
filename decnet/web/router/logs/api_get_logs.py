from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import get_current_user, repo
from decnet.web.models import LogsResponse

router = APIRouter()


@router.get("/logs", response_model=LogsResponse, tags=["Logs"])
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
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
