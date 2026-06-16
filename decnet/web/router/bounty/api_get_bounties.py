# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import BountyResponse

router = APIRouter()

# Cache the unfiltered default page — the UI/locust hit this constantly
# with no params. Filtered requests (bounty_type/search) bypass: rare
# and staleness matters for search.
_BOUNTY_TTL = 5.0
_DEFAULT_LIMIT = 50
_DEFAULT_OFFSET = 0
_bounty_cache: tuple[Optional[dict[str, Any]], float] = (None, 0.0)
_bounty_lock: Optional[asyncio.Lock] = None


def _reset_bounty_cache() -> None:
    global _bounty_cache, _bounty_lock
    _bounty_cache = (None, 0.0)
    _bounty_lock = None


async def _get_bounty_default_cached() -> dict[str, Any]:
    global _bounty_cache, _bounty_lock
    value, ts = _bounty_cache
    now = time.monotonic()
    if value is not None and now - ts < _BOUNTY_TTL:
        return value
    if _bounty_lock is None:
        _bounty_lock = asyncio.Lock()
    async with _bounty_lock:
        value, ts = _bounty_cache
        now = time.monotonic()
        if value is not None and now - ts < _BOUNTY_TTL:
            return value
        _data = await repo.get_bounties(
            limit=_DEFAULT_LIMIT, offset=_DEFAULT_OFFSET, bounty_type=None, search=None,
        )
        _total = await repo.get_total_bounties(bounty_type=None, search=None)
        value = {"total": _total, "limit": _DEFAULT_LIMIT, "offset": _DEFAULT_OFFSET, "data": _data}
        _bounty_cache = (value, time.monotonic())
        return value


@router.get("/bounty", response_model=BountyResponse, tags=["Bounty Vault"],
    responses={401: {"description": "Could not validate credentials"}, 403: {"description": "Insufficient permissions"}, 422: {"description": "Validation error"}},)
@_traced("api.get_bounties")
async def get_bounties(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    bounty_type: Optional[str] = None,
    search: Optional[str] = None,
    user: dict = Depends(require_viewer)
) -> dict[str, Any]:
    """Retrieve collected bounties (harvested credentials, payloads, etc.)."""
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    bt = _norm(bounty_type)
    s = _norm(search)

    if bt is None and s is None and limit == _DEFAULT_LIMIT and offset == _DEFAULT_OFFSET:
        return await _get_bounty_default_cached()

    _data = await repo.get_bounties(limit=limit, offset=offset, bounty_type=bt, search=s)
    _total = await repo.get_total_bounties(bounty_type=bt, search=s)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _data
    }
