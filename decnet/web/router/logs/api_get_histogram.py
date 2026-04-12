from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import get_current_user, repo

router = APIRouter()


@router.get("/logs/histogram", tags=["Logs"],
    responses={401: {"description": "Could not validate credentials"}, 422: {"description": "Validation error"}},)
async def get_logs_histogram(
    search: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    interval_minutes: int = Query(15, ge=1),
    current_user: str = Depends(get_current_user)
) -> list[dict[str, Any]]:
    return await repo.get_log_histogram(search=search, start_time=start_time, end_time=end_time, interval_minutes=interval_minutes)
