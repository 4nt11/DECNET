import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import AttackersResponse

router = APIRouter()

# Same pattern as /logs — cache the unfiltered total count; filtered
# counts go straight to the DB.
_TOTAL_TTL = 2.0
_total_cache: tuple[Optional[int], float] = (None, 0.0)
_total_lock: Optional[asyncio.Lock] = None


def _reset_total_cache() -> None:
    global _total_cache, _total_lock
    _total_cache = (None, 0.0)
    _total_lock = None


async def _get_total_attackers_cached() -> int:
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
        value = await repo.get_total_attackers()
        _total_cache = (value, time.monotonic())
        return value


@router.get(
    "/attackers",
    response_model=AttackersResponse,
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.get_attackers")
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
    if s is None and svc is None:
        _total = await _get_total_attackers_cached()
    else:
        _total = await repo.get_total_attackers(search=s, service=svc)

    # Bulk-join behavior rows for the IPs in this page to avoid N+1 queries.
    _ips = {row["ip"] for row in _data if row.get("ip")}
    _behaviors = await repo.get_behaviors_for_ips(_ips) if _ips else {}
    for row in _data:
        _ip: str | None = row.get("ip")
        row["behavior"] = _behaviors.get(_ip) if _ip is not None else None

    return {"total": _total, "limit": limit, "offset": offset, "data": _data}
