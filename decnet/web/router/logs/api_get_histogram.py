import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()

# /logs/histogram aggregates over the full logs table — expensive and
# polled constantly by the UI. Cache only the unfiltered default call
# (which is what the UI and locust hit); any filter bypasses.
_HISTOGRAM_TTL = 5.0
_DEFAULT_INTERVAL = 15
_histogram_cache: tuple[Optional[list[dict[str, Any]]], float] = (None, 0.0)
_histogram_lock: Optional[asyncio.Lock] = None


def _reset_histogram_cache() -> None:
    global _histogram_cache, _histogram_lock
    _histogram_cache = (None, 0.0)
    _histogram_lock = None


async def _get_histogram_cached() -> list[dict[str, Any]]:
    global _histogram_cache, _histogram_lock
    value, ts = _histogram_cache
    now = time.monotonic()
    if value is not None and now - ts < _HISTOGRAM_TTL:
        return value
    if _histogram_lock is None:
        _histogram_lock = asyncio.Lock()
    async with _histogram_lock:
        value, ts = _histogram_cache
        now = time.monotonic()
        if value is not None and now - ts < _HISTOGRAM_TTL:
            return value
        value = await repo.get_log_histogram(
            search=None, start_time=None, end_time=None, interval_minutes=_DEFAULT_INTERVAL,
        )
        _histogram_cache = (value, time.monotonic())
        return value


@router.get("/logs/histogram", tags=["Logs"],
    responses={401: {"description": "Could not validate credentials"}, 403: {"description": "Insufficient permissions"}, 422: {"description": "Validation error"}},)
@_traced("api.get_logs_histogram")
async def get_logs_histogram(
    search: Optional[str] = None,
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    interval_minutes: int = Query(15, ge=1),
    user: dict = Depends(require_viewer)
) -> list[dict[str, Any]]:
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    s = _norm(search)
    st = _norm(start_time)
    et = _norm(end_time)

    if s is None and st is None and et is None and interval_minutes == _DEFAULT_INTERVAL:
        return await _get_histogram_cached()
    return await repo.get_log_histogram(search=s, start_time=st, end_time=et, interval_minutes=interval_minutes)
