# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import StatsResponse

router = APIRouter()

# /stats is aggregate telemetry polled constantly by the UI and locust.
# A 5s window collapses thousands of concurrent calls — each of which
# runs SELECT count(*) FROM logs + SELECT count(DISTINCT attacker_ip) —
# into one DB hit per window.
_STATS_TTL = 5.0
_stats_cache: tuple[Optional[dict[str, Any]], float] = (None, 0.0)
_stats_lock: Optional[asyncio.Lock] = None


def _reset_stats_cache() -> None:
    global _stats_cache, _stats_lock
    _stats_cache = (None, 0.0)
    _stats_lock = None


async def _get_stats_cached() -> dict[str, Any]:
    global _stats_cache, _stats_lock
    value, ts = _stats_cache
    now = time.monotonic()
    if value is not None and now - ts < _STATS_TTL:
        return value
    if _stats_lock is None:
        _stats_lock = asyncio.Lock()
    async with _stats_lock:
        value, ts = _stats_cache
        now = time.monotonic()
        if value is not None and now - ts < _STATS_TTL:
            return value
        value = await repo.get_stats_summary()
        _stats_cache = (value, time.monotonic())
        return value


@router.get("/stats", response_model=StatsResponse, tags=["Observability"],
    responses={401: {"description": "Could not validate credentials"}, 403: {"description": "Insufficient permissions"}, 422: {"description": "Validation error"}},)
@_traced("api.get_stats")
async def get_stats(user: dict = Depends(require_viewer)) -> dict[str, Any]:
    return await _get_stats_cached()
