# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends

from decnet.env import DECNET_DEVELOPER
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import UserResponse

router = APIRouter()

_DEFAULT_DEPLOYMENT_LIMIT = 10
_DEFAULT_MUTATION_INTERVAL = "30m"

# Cache config_limits / config_globals reads — these change on rare admin
# writes but get polled constantly by the UI and locust.
_STATE_TTL = 5.0
_state_cache: dict[str, tuple[Optional[dict[str, Any]], float]] = {}
_state_locks: dict[str, asyncio.Lock] = {}

# Admin branch fetched repo.list_users() on every /config call — cache 5s,
# invalidate on user create/update/delete so the admin UI stays consistent.
_USERS_TTL = 5.0
_users_cache: tuple[Optional[list[dict[str, Any]]], float] = (None, 0.0)
_users_lock: Optional[asyncio.Lock] = None


def _reset_state_cache() -> None:
    """Reset cached config state — used by tests."""
    global _users_cache, _users_lock
    _state_cache.clear()
    # Drop any locks bound to the previous event loop — reusing one from
    # a dead loop deadlocks the next test.
    _state_locks.clear()
    _users_cache = (None, 0.0)
    _users_lock = None


def invalidate_list_users_cache() -> None:
    global _users_cache
    _users_cache = (None, 0.0)


async def _get_list_users_cached() -> list[dict[str, Any]]:
    global _users_cache, _users_lock
    value, ts = _users_cache
    now = time.monotonic()
    if value is not None and now - ts < _USERS_TTL:
        return value
    if _users_lock is None:
        _users_lock = asyncio.Lock()
    async with _users_lock:
        value, ts = _users_cache
        now = time.monotonic()
        if value is not None and now - ts < _USERS_TTL:
            return value
        value = await repo.list_users()
        _users_cache = (value, time.monotonic())
        return value


async def _get_state_cached(name: str) -> Optional[dict[str, Any]]:
    entry = _state_cache.get(name)
    now = time.monotonic()
    if entry is not None and now - entry[1] < _STATE_TTL:
        return entry[0]
    lock = _state_locks.setdefault(name, asyncio.Lock())
    async with lock:
        entry = _state_cache.get(name)
        now = time.monotonic()
        if entry is not None and now - entry[1] < _STATE_TTL:
            return entry[0]
        value = await repo.get_state(name)
        _state_cache[name] = (value, time.monotonic())
        return value


@router.get(
    "/config",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.get_config")
async def api_get_config(user: dict = Depends(require_viewer)) -> dict:
    limits_state = await _get_state_cached("config_limits")
    globals_state = await _get_state_cached("config_globals")

    deployment_limit = (
        limits_state.get("deployment_limit", _DEFAULT_DEPLOYMENT_LIMIT)
        if limits_state
        else _DEFAULT_DEPLOYMENT_LIMIT
    )
    global_mutation_interval = (
        globals_state.get("global_mutation_interval", _DEFAULT_MUTATION_INTERVAL)
        if globals_state
        else _DEFAULT_MUTATION_INTERVAL
    )

    base = {
        "role": user["role"],
        "deployment_limit": deployment_limit,
        "global_mutation_interval": global_mutation_interval,
    }

    if user["role"] == "admin":
        all_users = await _get_list_users_cached()
        base["users"] = [
            UserResponse(
                uuid=u["uuid"],
                username=u["username"],
                role=u["role"],
                must_change_password=u["must_change_password"],
            ).model_dump()
            for u in all_users
        ]
        if DECNET_DEVELOPER:
            base["developer_mode"] = True

    return base
