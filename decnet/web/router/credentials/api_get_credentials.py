import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import CredentialsResponse

router = APIRouter()

# Mirror the Bounty cache pattern: the dashboard hits the unfiltered
# default page constantly. Filtered requests bypass — staleness matters
# when an operator is searching for a specific principal/IP.
_CRED_TTL = 5.0
_DEFAULT_LIMIT = 50
_DEFAULT_OFFSET = 0
_cred_cache: tuple[Optional[dict[str, Any]], float] = (None, 0.0)
_cred_lock: Optional[asyncio.Lock] = None


def _reset_credentials_cache() -> None:
    global _cred_cache, _cred_lock
    _cred_cache = (None, 0.0)
    _cred_lock = None


async def _get_credentials_default_cached() -> dict[str, Any]:
    global _cred_cache, _cred_lock
    value, ts = _cred_cache
    now = time.monotonic()
    if value is not None and now - ts < _CRED_TTL:
        return value
    if _cred_lock is None:
        _cred_lock = asyncio.Lock()
    async with _cred_lock:
        value, ts = _cred_cache
        now = time.monotonic()
        if value is not None and now - ts < _CRED_TTL:
            return value
        _data = await repo.get_credentials(
            limit=_DEFAULT_LIMIT, offset=_DEFAULT_OFFSET,
            search=None, service=None, attacker_ip=None,
        )
        _total = await repo.get_total_credentials(
            search=None, service=None, attacker_ip=None,
        )
        value = {"total": _total, "limit": _DEFAULT_LIMIT, "offset": _DEFAULT_OFFSET, "data": _data}
        _cred_cache = (value, time.monotonic())
        return value


@router.get(
    "/credentials",
    response_model=CredentialsResponse,
    tags=["Credentials"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.get_credentials")
async def get_credentials(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    search: Optional[str] = None,
    service: Optional[str] = None,
    attacker_ip: Optional[str] = None,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Retrieve captured credentials (deduped by attacker/decky/service/secret)."""
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    s = _norm(search)
    svc = _norm(service)
    aip = _norm(attacker_ip)

    if (
        s is None
        and svc is None
        and aip is None
        and limit == _DEFAULT_LIMIT
        and offset == _DEFAULT_OFFSET
    ):
        return await _get_credentials_default_cached()

    _data = await repo.get_credentials(
        limit=limit, offset=offset, search=s, service=svc, attacker_ip=aip,
    )
    _total = await repo.get_total_credentials(
        search=s, service=svc, attacker_ip=aip,
    )
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _data,
    }
