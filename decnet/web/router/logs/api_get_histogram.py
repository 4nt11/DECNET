from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.web.dependencies import get_current_user, repo

router = APIRouter()


@router.get("/logs/histogram", tags=["Logs"],
    responses={401: {"description": "Could not validate credentials"}, 422: {"description": "Validation error"}},)
async def get_logs_histogram(
    search: Optional[str] = None,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    interval_minutes: int = Query(15, ge=1),
    current_user: str = Depends(get_current_user)
) -> list[dict[str, Any]]:
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    s = _norm(search)
    st = _norm(start_time)
    et = _norm(end_time)

    return await repo.get_log_histogram(search=s, start_time=st, end_time=et, interval_minutes=interval_minutes)
