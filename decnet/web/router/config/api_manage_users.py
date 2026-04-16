import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.auth import get_password_hash
from decnet.web.dependencies import require_admin, repo
from decnet.web.db.models import (
    CreateUserRequest,
    UpdateUserRoleRequest,
    ResetUserPasswordRequest,
    UserResponse,
)

router = APIRouter()


@router.post(
    "/config/users",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        409: {"description": "Username already exists"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.create_user")
async def api_create_user(
    req: CreateUserRequest,
    admin: dict = Depends(require_admin),
) -> UserResponse:
    existing = await repo.get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    user_uuid = str(_uuid.uuid4())
    await repo.create_user({
        "uuid": user_uuid,
        "username": req.username,
        "password_hash": get_password_hash(req.password),
        "role": req.role,
        "must_change_password": True,  # nosec B105 — not a password
    })
    return UserResponse(
        uuid=user_uuid,
        username=req.username,
        role=req.role,
        must_change_password=True,
    )


@router.delete(
    "/config/users/{user_uuid}",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required / cannot delete self"},
        404: {"description": "User not found"},
    },
)
@_traced("api.delete_user")
async def api_delete_user(
    user_uuid: str,
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    if user_uuid == admin["uuid"]:
        raise HTTPException(status_code=403, detail="Cannot delete your own account")

    deleted = await repo.delete_user(user_uuid)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted"}


@router.put(
    "/config/users/{user_uuid}/role",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required / cannot change own role"},
        404: {"description": "User not found"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.update_user_role")
async def api_update_user_role(
    user_uuid: str,
    req: UpdateUserRoleRequest,
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    if user_uuid == admin["uuid"]:
        raise HTTPException(status_code=403, detail="Cannot change your own role")

    target = await repo.get_user_by_uuid(user_uuid)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    await repo.update_user_role(user_uuid, req.role)
    return {"message": "User role updated"}


@router.put(
    "/config/users/{user_uuid}/reset-password",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        404: {"description": "User not found"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.reset_user_password")
async def api_reset_user_password(
    user_uuid: str,
    req: ResetUserPasswordRequest,
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    target = await repo.get_user_by_uuid(user_uuid)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    await repo.update_user_password(
        user_uuid,
        get_password_hash(req.new_password),
        must_change_password=True,
    )
    return {"message": "Password reset successfully"}
