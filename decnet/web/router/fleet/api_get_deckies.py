# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()

# /deckies is full fleet inventory — polled by the UI and under locust.
# Fleet state changes on deploy/teardown (seconds to minutes); a 5s window
# collapses the read storm into one DB hit.
_DECKIES_TTL = 5.0
_deckies_cache: tuple[Optional[list[dict[str, Any]]], float] = (None, 0.0)
_deckies_lock: Optional[asyncio.Lock] = None


def _reset_deckies_cache() -> None:
    global _deckies_cache, _deckies_lock
    _deckies_cache = (None, 0.0)
    _deckies_lock = None


async def _get_deckies_cached() -> list[dict[str, Any]]:
    global _deckies_cache, _deckies_lock
    value, ts = _deckies_cache
    now = time.monotonic()
    if value is not None and now - ts < _DECKIES_TTL:
        return value
    if _deckies_lock is None:
        _deckies_lock = asyncio.Lock()
    async with _deckies_lock:
        value, ts = _deckies_cache
        now = time.monotonic()
        if value is not None and now - ts < _DECKIES_TTL:
            return value
        value = await repo.get_deckies()
        _deckies_cache = (value, time.monotonic())
        return value


@router.get("/deckies", tags=["Fleet Management"],
    responses={401: {"description": "Could not validate credentials"}, 403: {"description": "Insufficient permissions"}, 422: {"description": "Validation error"}},)
@_traced("api.get_deckies")
async def get_deckies(user: dict = Depends(require_viewer)) -> list[dict[str, Any]]:
    return await _get_deckies_cached()
