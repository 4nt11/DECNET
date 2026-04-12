from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.web.auth import get_password_hash, verify_password
from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import ChangePasswordRequest

router = APIRouter()


@router.post(
    "/auth/change-password",
    tags=["Authentication"],
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        422: {"description": "Validation error"}
    },
)
async def change_password(request: ChangePasswordRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    _user: Optional[dict[str, Any]] = await repo.get_user_by_uuid(current_user)
    if not _user or not verify_password(request.old_password, _user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect old password",
        )

    _new_hash: str = get_password_hash(request.new_password)
    await repo.update_user_password(current_user, _new_hash, must_change_password=False)
    return {"message": "Password updated successfully"}
