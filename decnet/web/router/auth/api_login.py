# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import timedelta
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, status

from decnet.telemetry import traced as _traced
from decnet.web.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    averify_password,
    create_access_token,
)
from decnet.web.dependencies import get_user_by_username_cached
from decnet.web.db.models import LoginRequest, Token
from decnet.web.limiter import limiter, login_ip_key, login_username_key

router = APIRouter()


# Two independent buckets, tripping either → 429:
#
#   - per-IP   (login_ip_key):       catches a botnet hitting one account.
#   - per-user (login_username_key): catches distributed credential
#                                    stuffing against one account.
#
# Limits: 10 attempts per 5 minutes per bucket. Buckets are process-local
# (memory://); see decnet/web/limiter.py for the rationale. Buckets do
# NOT reset on successful login — a legitimate user tripping the limit
# via fat-fingering will need to wait the window out. 10 tries is
# generous; a rolling window naturally drains.
@router.post(
    "/auth/login",
    response_model=Token,
    tags=["Authentication"],
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Incorrect username or password"},
        422: {"description": "Validation error"},
        429: {"description": "Too many login attempts — retry after the window resets"},
    },
)
@limiter.limit("10/5 minutes", key_func=login_ip_key)
@limiter.limit("10/5 minutes", key_func=login_username_key)  # type: ignore[arg-type]
@_traced("api.login")
async def login(request: Request, payload: LoginRequest) -> dict[str, Any]:
    _user: Optional[dict[str, Any]] = await get_user_by_username_cached(payload.username)
    if not _user or not await averify_password(payload.password, _user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _access_token_expires: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Token uses uuid instead of sub; jti is the per-token id the denylist
    # keys on (logout). create_access_token stamps exp + iat.
    _access_token: str = create_access_token(
        data={"uuid": _user["uuid"], "jti": uuid4().hex},
        expires_delta=_access_token_expires,
    )
    return {
        "access_token": _access_token,
        "token_type": "bearer",  # nosec B105 — OAuth2 token type, not a password
        "must_change_password": bool(_user.get("must_change_password", False))
    }
