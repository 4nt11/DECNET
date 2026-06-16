# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional

import jwt
from fastapi import HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

from decnet.web.auth import (
    ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_TYPE,
    SECRET_KEY,
)
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
#
# REVOCATION-WINDOW NOTE (V2.1.8, accept-risk): these per-process caches bound
# how long a *stale* user/username/denylist row can be served. Single-process:
# a role downgrade or password change is reflected within ~_USER_TTL (10s) even
# if the in-process invalidate_user_cache hook is missed; the local write path
# invalidates immediately. Multi-worker (gunicorn/uvicorn --workers>1) gives
# each worker its own cache, so the worst-case cross-worker staleness is also
# ~10s and would need a shared cache (Redis) to collapse to zero. This staleness
# is NOT the authoritative revocation control: JWT bulk-revoke via the user's
# tokens_valid_from cutoff (enforced in _resolve_token) is the hard cutoff and
# is unaffected by these caches.
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

# Denylist membership cache for revoked jti lookups. Same 10s envelope as the
# user cache: a token revoked elsewhere stops working within _REVOKED_TTL. In
# this process we drop the stale entry on revoke (see invalidate_token_cache),
# so logout is immediate locally; the TTL only bounds cross-worker staleness.
_REVOKED_TTL = 10.0
_revoked_cache: dict[str, tuple[bool, float]] = {}
_revoked_cache_lock: Optional[asyncio.Lock] = None


def _reset_user_cache() -> None:
    global _user_cache, _user_cache_lock, _username_cache, _username_cache_lock
    global _revoked_cache, _revoked_cache_lock
    _user_cache = {}
    _user_cache_lock = None
    _username_cache = {}
    _username_cache_lock = None
    _revoked_cache = {}
    _revoked_cache_lock = None


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


def invalidate_token_cache(jti: Optional[str] = None) -> None:
    """Drop a single jti (or the whole denylist cache) so the next request
    re-reads revocation state from the DB. Called right after ``revoke_token``
    so a logged-out token stops working immediately in this process."""
    if jti is None:
        _revoked_cache.clear()
    else:
        _revoked_cache.pop(jti, None)


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


async def _is_revoked_cached(jti: str) -> bool:
    global _revoked_cache_lock
    entry = _revoked_cache.get(jti)
    now = time.monotonic()
    if entry is not None and now - entry[1] < _REVOKED_TTL:
        return entry[0]
    if _revoked_cache_lock is None:
        _revoked_cache_lock = asyncio.Lock()
    async with _revoked_cache_lock:
        entry = _revoked_cache.get(jti)
        now = time.monotonic()
        if entry is not None and now - entry[1] < _REVOKED_TTL:
            return entry[0]
        revoked = await repo.is_token_revoked(jti)
        _revoked_cache[jti] = (revoked, time.monotonic())
        return revoked


_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def _epoch(value: Any) -> float:
    """Coerce a JWT ``iat`` (int seconds) or a stored datetime to UTC epoch
    seconds so the two can be compared regardless of source. Naive datetimes
    (SQLite round-trips lose tzinfo) are treated as the UTC we wrote."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
        return aware.timestamp()
    raise _CREDENTIALS_EXCEPTION


def _decode_payload(token: str) -> dict[str, Any]:
    """Decode + signature/expiry-verify a raw JWT, or raise 401.

    Beyond signature + expiry, this pins the issuer and audience and requires
    the registered claims to be present, so a token minted with the same shared
    secret for a different purpose (or omitting exp/iat/iss/aud) is rejected.
    ``uuid`` (not ``sub``) is this app's identity claim, so it is in ``require``.
    ``typ`` is a custom payload claim PyJWT does not validate natively, so it is
    checked explicitly below.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "uuid"]},
        )
    except jwt.PyJWTError:
        raise _CREDENTIALS_EXCEPTION
    if payload.get("uuid") is None:
        raise _CREDENTIALS_EXCEPTION
    if payload.get("typ") != JWT_TYPE:
        raise _CREDENTIALS_EXCEPTION
    return payload


async def _resolve_token(token: str) -> tuple[str, dict[str, Any]]:
    """Decode a token, load its user, and enforce revocation. Returns
    ``(user_uuid, user_dict)`` or raises 401. Single chokepoint so every auth
    path (header, SSE query param, role gates) shares identical revocation
    semantics."""
    payload = _decode_payload(token)
    user_uuid: str = payload["uuid"]
    user = await _get_user_cached(user_uuid)
    if not user:
        # Unknown / deleted user — also covers the user-delete revocation case.
        raise _CREDENTIALS_EXCEPTION
    # 1. Legacy tokens minted before jti existed cannot be revoked — fail closed
    #    so a deploy of this feature forces exactly one re-login.
    jti = payload.get("jti")
    if not jti:
        raise _CREDENTIALS_EXCEPTION
    # 2. Bulk cutoff: password/role change moves tokens_valid_from forward.
    #    JWT iat is whole-seconds, so floor the cutoff to whole seconds too —
    #    otherwise a re-login landing in the SAME second as the change gets an
    #    iat that truncates below a sub-second cutoff and is wrongly rejected.
    #    Cost: tokens issued earlier in that same second survive (≤1s), which is
    #    negligible against a 24h lifetime.
    cutoff = user.get("tokens_valid_from")
    if cutoff is not None and _epoch(payload.get("iat", 0)) < int(_epoch(cutoff)):
        raise _CREDENTIALS_EXCEPTION
    # 3. Single-token denylist (logout).
    if await _is_revoked_cached(jti):
        raise _CREDENTIALS_EXCEPTION
    return user_uuid, user


def _bearer_from_header(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth.split(" ", 1)[1]
    return None


async def _resolve_request(request: Request) -> tuple[str, dict[str, Any]]:
    """Bearer-header variant of :func:`_resolve_token`."""
    token = _bearer_from_header(request)
    if not token:
        raise _CREDENTIALS_EXCEPTION
    return await _resolve_token(token)


async def get_token_claims(request: Request) -> dict[str, Any]:
    """Return the validated claims of the presented Bearer token (decode +
    signature + user-exists + revocation checks, but NOT must_change). Used by
    logout, which needs the token's own ``jti``/``exp`` to denylist *this*
    session — and must still reject an already-revoked token."""
    token = _bearer_from_header(request)
    if not token:
        raise _CREDENTIALS_EXCEPTION
    await _resolve_token(token)  # enforce user-exists + revocation; raises 401
    return _decode_payload(token)


# ---------------------------------------------------------------------------
# SSE stream tickets (V3.1.1)
# ---------------------------------------------------------------------------
# EventSource cannot set an Authorization header, so SSE auth historically rode
# in ?token=<JWT>, leaking the full-lifetime bearer into access/proxy logs,
# browser history, and Referer. Instead the client exchanges its header JWT for
# a single-use, short-lived OPAQUE ticket via POST /api/v1/auth/sse-ticket and
# connects with ?ticket=<opaque>. The JWT never appears in any URL.
#
# Security-boundary store — FAIL CLOSED. The map is keyed on the opaque ticket
# and holds (expiry_monotonic, bound_identity). Redemption validates presence +
# freshness, then DELETES the entry (single-use). Unknown / expired / reused
# tickets all resolve to 401.
#
# This is a MODULE-LEVEL dict: tickets live only in the process that minted
# them. A multi-process / multi-worker deployment needs a SHARED store (Redis,
# DB) so a ticket minted on worker A can be redeemed on worker B — out of scope
# here, deliberately. No background sweeper daemon (project rule: library, not
# new worker); expiry is enforced opportunistically on every redeem + mint.
_SSE_TICKET_TTL = 60.0  # seconds
_sse_tickets: dict[str, tuple[float, dict[str, Any]]] = {}


def _reset_sse_tickets() -> None:
    """Test hook: drop all outstanding stream tickets."""
    _sse_tickets.clear()


def _sweep_sse_tickets(now: Optional[float] = None) -> None:
    """Opportunistic eviction of expired tickets. O(n) over a tiny map (tickets
    are single-use and 60s-lived), called on every mint/redeem — no daemon."""
    _now = time.monotonic() if now is None else now
    expired = [t for t, (exp, _) in _sse_tickets.items() if exp <= _now]
    for t in expired:
        _sse_tickets.pop(t, None)


def mint_sse_ticket(user_uuid: str, role: str) -> str:
    """Mint a single-use, 60s opaque SSE ticket bound to ``user_uuid``+``role``.

    Called by POST /auth/sse-ticket AFTER the header JWT has been validated, so
    the bound identity is already trusted. Returns the opaque token the client
    passes as ?ticket=. Sweeps expired entries on the way in.
    """
    _sweep_sse_tickets()
    ticket = secrets.token_urlsafe(32)
    expiry = time.monotonic() + _SSE_TICKET_TTL
    _sse_tickets[ticket] = (expiry, {"uuid": user_uuid, "role": role})
    return ticket


def _redeem_sse_ticket(ticket: str) -> dict[str, Any]:
    """Redeem a stream ticket: validate exists + unexpired, then DELETE it
    (single-use). Returns the bound ``{"uuid","role"}`` identity or raises 401.
    Fail closed: unknown / expired / already-redeemed all raise."""
    now = time.monotonic()
    _sweep_sse_tickets(now)
    entry = _sse_tickets.pop(ticket, None)  # pop = single-use, even on expiry
    if entry is None:
        raise _CREDENTIALS_EXCEPTION
    expiry, identity = entry
    if expiry <= now:
        raise _CREDENTIALS_EXCEPTION
    return identity


async def get_current_user(request: Request) -> str:
    """Auth dependency — enforces must_change_password."""
    _user_uuid, _user = await _resolve_request(request)
    if _user.get("must_change_password"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before accessing this resource",
        )
    return _user_uuid


async def get_current_user_unchecked(request: Request) -> str:
    """Auth dependency — skips must_change_password enforcement (but still
    enforces signature, user existence, and revocation).
    Use only for endpoints that must remain reachable with the flag set (e.g. change-password).
    """
    _user_uuid, _user = await _resolve_request(request)
    return _user_uuid


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
        _user_uuid, user = await _resolve_request(request)
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
    """Like ``require_role`` but for SSE endpoints.

    Two ingress paths:
      * Bearer header → full ``_resolve_token`` (revocation + cutoff enforced).
      * ?ticket=<opaque> → single-use stream ticket minted by /auth/sse-ticket,
        which already validated the header JWT and bound the uuid+role. The
        ticket carries no jti, so the per-token denylist cannot apply here; the
        60s single-use lifetime is the bounded exposure we accept for SSE.

    Raw ?token=<JWT> is intentionally NOT accepted (V3.1.1)."""
    async def _check(request: Request, ticket: Optional[str] = None) -> dict:
        header_token = _bearer_from_header(request)
        if header_token:
            _user_uuid, user = await _resolve_token(header_token)
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
        if not ticket:
            raise _CREDENTIALS_EXCEPTION
        identity = _redeem_sse_ticket(ticket)
        if identity["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return identity
    return _check


require_admin = require_role("admin")
require_viewer = require_role("viewer", "admin")
require_stream_viewer = require_stream_role("viewer", "admin")
