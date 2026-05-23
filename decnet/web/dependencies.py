# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

import jwt
from fastapi import HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

from decnet.web.auth import ALGORITHM, SECRET_KEY
from decnet.web.db.repository import BaseRepository
from decnet.web.db.factory import get_repository

# Shared repository singleton
_repo: Optional[BaseRepository] = None

def get_repo() -> BaseRepository:
    """FastAPI dependency to inject the configured repository."""
    global _repo
    if _repo is None:
        _repo = get_repository()
    return _repo

repo = get_repo()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# Per-request user lookup was the hidden tax behind every authed endpoint —
# SELECT users WHERE uuid=? ran once per call, serializing through aiosqlite.
# 10s TTL is well below JWT expiry and we invalidate on all user writes.
_USER_TTL = 10.0
_user_cache: dict[str, tuple[Optional[dict[str, Any]], float]] = {}
_user_cache_lock: Optional[asyncio.Lock] = None

# Username cache for the login hot path. Short TTL — the bcrypt verify
# still runs against the cached hash, so security is unchanged. The
# staleness window is: if a password is changed, the old password is
# usable for up to _USERNAME_TTL seconds until the cache expires (or
# invalidate_user_cache fires). We invalidate on every user write.
# Missing lookups are NOT cached to avoid locking out a just-created user.
_USERNAME_TTL = 5.0
_username_cache: dict[str, tuple[dict[str, Any], float]] = {}
_username_cache_lock: Optional[asyncio.Lock] = None


def _reset_user_cache() -> None:
    global _user_cache, _user_cache_lock, _username_cache, _username_cache_lock
    _user_cache = {}
    _user_cache_lock = None
    _username_cache = {}
    _username_cache_lock = None


def invalidate_user_cache(user_uuid: Optional[str] = None) -> None:
    """Drop a single user (or all users) from the auth caches.

    Callers: password change, role change, user create/delete.
    The username cache is always cleared wholesale — we don't track
    uuid→username and user writes are rare, so the cost is trivial.
    """
    if user_uuid is None:
        _user_cache.clear()
    else:
        _user_cache.pop(user_uuid, None)
    _username_cache.clear()


async def get_user_by_username_cached(username: str) -> Optional[dict[str, Any]]:
    """Cached read of get_user_by_username for the login path.

    Positive hits are cached for _USERNAME_TTL seconds. Misses bypass
    the cache so a freshly-created user can log in immediately.
    """
    global _username_cache_lock
    entry = _username_cache.get(username)
    now = time.monotonic()
    if entry is not None and now - entry[1] < _USERNAME_TTL:
        return entry[0]
    if _username_cache_lock is None:
        _username_cache_lock = asyncio.Lock()
    async with _username_cache_lock:
        entry = _username_cache.get(username)
        now = time.monotonic()
        if entry is not None and now - entry[1] < _USERNAME_TTL:
            return entry[0]
        user = await repo.get_user_by_username(username)
        if user is not None:
            _username_cache[username] = (user, time.monotonic())
        return user


async def _get_user_cached(user_uuid: str) -> Optional[dict[str, Any]]:
    global _user_cache_lock
    entry = _user_cache.get(user_uuid)
    now = time.monotonic()
    if entry is not None and now - entry[1] < _USER_TTL:
        return entry[0]
    if _user_cache_lock is None:
        _user_cache_lock = asyncio.Lock()
    async with _user_cache_lock:
        entry = _user_cache.get(user_uuid)
        now = time.monotonic()
        if entry is not None and now - entry[1] < _USER_TTL:
            return entry[0]
        user = await repo.get_user_by_uuid(user_uuid)
        _user_cache[user_uuid] = (user, time.monotonic())
        return user


_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def _jwt_to_uuid(token: str) -> str:
    """Decode a raw JWT string and return the user UUID, or raise 401."""
    try:
        payload: dict[str, Any] = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_uuid: Optional[str] = payload.get("uuid")
        if user_uuid is None:
            raise _CREDENTIALS_EXCEPTION
        return user_uuid
    except jwt.PyJWTError:
        raise _CREDENTIALS_EXCEPTION


def _bearer_from_header(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth.split(" ", 1)[1]
    return None


async def get_stream_user(request: Request, token: Optional[str] = None) -> str:
    """Auth dependency for SSE endpoints — accepts Bearer header OR ?token= query param.
    EventSource does not support custom headers, so the query-string fallback is intentional here only.
    """
    resolved = _bearer_from_header(request) or token
    if not resolved:
        raise _CREDENTIALS_EXCEPTION
    return _jwt_to_uuid(resolved)


async def _decode_token(request: Request) -> str:
    """Decode and validate a Bearer JWT, returning the user UUID."""
    token = _bearer_from_header(request)
    if not token:
        raise _CREDENTIALS_EXCEPTION
    return _jwt_to_uuid(token)


async def get_current_user(request: Request) -> str:
    """Auth dependency — enforces must_change_password."""
    _user_uuid = await _decode_token(request)
    _user = await _get_user_cached(_user_uuid)
    if _user and _user.get("must_change_password"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before accessing this resource",
        )
    return _user_uuid


async def get_current_user_unchecked(request: Request) -> str:
    """Auth dependency — skips must_change_password enforcement.
    Use only for endpoints that must remain reachable with the flag set (e.g. change-password).
    """
    return await _decode_token(request)


# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

def require_role(*allowed_roles: str):
    """Factory that returns a FastAPI dependency enforcing role membership.

    Inlines JWT decode + user lookup + must_change_password + role check so the
    user is only loaded from the DB once per request (not once in
    ``get_current_user`` and again here).  Returns the full user dict so
    endpoints can inspect ``user["uuid"]``, ``user["role"]``, etc.
    """
    async def _check(request: Request) -> dict:
        user_uuid = await _decode_token(request)
        user = await _get_user_cached(user_uuid)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if user.get("must_change_password"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password change required before accessing this resource",
            )
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return _check


def require_stream_role(*allowed_roles: str):
    """Like ``require_role`` but for SSE endpoints that accept a query-param token."""
    async def _check(request: Request, token: Optional[str] = None) -> dict:
        user_uuid = await get_stream_user(request, token)
        user = await _get_user_cached(user_uuid)
        if not user or user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return _check


require_admin = require_role("admin")
require_viewer = require_role("viewer", "admin")
require_stream_viewer = require_stream_role("viewer", "admin")
