# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from decnet.telemetry import traced as _traced
from decnet.web.auth import ahash_password, averify_password
from decnet.web.dependencies import get_current_user_unchecked, invalidate_user_cache, repo
from decnet.web.db.models import ChangePasswordRequest, MessageResponse
from decnet.web.limiter import limiter

router = APIRouter()


@router.post(
    "/auth/change-password",
    tags=["Authentication"],
    response_model=MessageResponse,
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        422: {"description": "Validation error"},
        429: {"description": "Too many password-change attempts — retry after the window resets"},
    },
)
@limiter.limit("5/minute")
@_traced("api.change_password")
async def change_password(request: Request, body: ChangePasswordRequest, current_user: str = Depends(get_current_user_unchecked)) -> dict[str, str]:
    _user: Optional[dict[str, Any]] = await repo.get_user_by_uuid(current_user)
    if not _user or not await averify_password(body.old_password, _user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect old password",
        )

    _new_hash: str = await ahash_password(body.new_password)
    await repo.update_user_password(current_user, _new_hash, must_change_password=False)
    # Changing a password revokes every existing session for this user (incl.
    # the current one): the caller's next request 401s and re-authenticates.
    await repo.set_tokens_valid_from(current_user, datetime.now(timezone.utc))
    invalidate_user_cache(current_user)
    return {"message": "Password updated successfully"}
