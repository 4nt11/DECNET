# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import LogsResponse

router = APIRouter()

# Cache the unfiltered total-logs count. Filtered counts bypass the cache
# (rare, freshness matters for search). SELECT count(*) FROM logs is a
# full scan and gets hammered by paginating clients.
_TOTAL_TTL = 2.0
_total_cache: tuple[Optional[int], float] = (None, 0.0)
_total_lock: Optional[asyncio.Lock] = None


def _reset_total_cache() -> None:
    global _total_cache, _total_lock
    _total_cache = (None, 0.0)
    _total_lock = None


async def _get_total_logs_cached() -> int:
    global _total_cache, _total_lock
    value, ts = _total_cache
    now = time.monotonic()
    if value is not None and now - ts < _TOTAL_TTL:
        return value
    if _total_lock is None:
        _total_lock = asyncio.Lock()
    async with _total_lock:
        value, ts = _total_cache
        now = time.monotonic()
        if value is not None and now - ts < _TOTAL_TTL:
            return value
        value = await repo.get_total_logs()
        _total_cache = (value, time.monotonic())
        return value


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
    if s is None and st is None and et is None:
        _total: int = await _get_total_logs_cached()
    else:
        _total = await repo.get_total_logs(search=s, start_time=st, end_time=et)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _logs
    }
