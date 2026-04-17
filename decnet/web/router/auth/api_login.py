from datetime import timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, status

from decnet.telemetry import traced as _traced
from decnet.web.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    averify_password,
    create_access_token,
)
from decnet.web.dependencies import repo
from decnet.web.db.models import LoginRequest, Token

router = APIRouter()


@router.post(
    "/auth/login",
    response_model=Token,
    tags=["Authentication"],
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Incorrect username or password"},
        422: {"description": "Validation error"}
    },
)
@_traced("api.login")
async def login(request: LoginRequest) -> dict[str, Any]:
    _user: Optional[dict[str, Any]] = await repo.get_user_by_username(request.username)
    if not _user or not await averify_password(request.password, _user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _access_token_expires: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Token uses uuid instead of sub
    _access_token: str = create_access_token(
        data={"uuid": _user["uuid"]}, expires_delta=_access_token_expires
    )
    return {
        "access_token": _access_token,
        "token_type": "bearer",  # nosec B105 — OAuth2 token type, not a password
        "must_change_password": bool(_user.get("must_change_password", False))
    }
