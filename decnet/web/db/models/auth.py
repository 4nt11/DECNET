# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auth + user-management tables and DTOs."""
from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field as PydanticField, field_validator
from sqlmodel import Field, SQLModel


def _reject_over_72_bytes(v: str) -> str:
    """bcrypt silently truncates at 72 bytes; reject instead to avoid
    collision/confusion between passwords that share a 72-byte prefix."""
    if len(v.encode("utf-8")) > 72:
        raise ValueError("password must not exceed 72 UTF-8 bytes (bcrypt limit)")
    return v


class User(SQLModel, table=True):
    __tablename__ = "users"
    uuid: str = Field(primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: str = Field(default="viewer")
    must_change_password: bool = Field(default=False)
    # Bulk session-revocation cutoff: any token whose ``iat`` predates this
    # instant is rejected. Bumped to "now" on password change, role change,
    # and admin password reset. NULL means no bulk revocation has occurred.
    tokens_valid_from: Optional[datetime] = Field(default=None)


class RevokedToken(SQLModel, table=True):
    """A single JWT explicitly revoked via logout, keyed on its ``jti``.

    This denylist holds only explicitly-revoked, not-yet-expired tokens, so it
    stays tiny — ``revoke_token`` opportunistically prunes rows past expiry on
    every insert. Bulk "log out everywhere" events use ``User.tokens_valid_from``
    instead, because there is no per-user registry of live ``jti``s to enumerate.
    """
    __tablename__ = "revoked_tokens"
    jti: str = Field(primary_key=True)
    user_uuid: str = Field(index=True)  # User.uuid; no FK (independent audit row)
    expires_at: datetime = Field(index=True)  # token exp; row is prunable past this
    revoked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# --- API Request/Response Models (Pydantic) ---

class Token(BaseModel):
    access_token: str
    token_type: str
    must_change_password: bool = False


class LoginRequest(BaseModel):
    username: str
    password: str = PydanticField(..., max_length=72)


class ChangePasswordRequest(BaseModel):
    old_password: str = PydanticField(..., max_length=72)
    # min_length=12 aligns with the DECNET_ADMIN_PASSWORD >=12 policy. The
    # forced first-login flow routes through /auth/change-password, so without a
    # floor a seeded admin could clear must_change_password with a 1-char secret.
    new_password: str = PydanticField(..., min_length=12, max_length=72)

    @field_validator("old_password", "new_password", mode="after")
    @classmethod
    def _check_byte_limit(cls, v: str) -> str:
        return _reject_over_72_bytes(v)


class SSETicketResponse(BaseModel):
    """Single-use, short-lived opaque ticket the dashboard exchanges its header
    JWT for, then passes to an SSE endpoint as ?ticket= (EventSource cannot set
    an Authorization header). See decnet.web.dependencies SSE ticket store."""
    ticket: str
    expires_in: int


# --- Configuration Models ---

class CreateUserRequest(BaseModel):
    username: str = PydanticField(..., min_length=1, max_length=64)
    password: str = PydanticField(..., min_length=12, max_length=72)
    role: Literal["admin", "viewer"] = "viewer"

    @field_validator("password", mode="after")
    @classmethod
    def _check_byte_limit(cls, v: str) -> str:
        return _reject_over_72_bytes(v)


class UpdateUserRoleRequest(BaseModel):
    role: Literal["admin", "viewer"]


class ResetUserPasswordRequest(BaseModel):
    new_password: str = PydanticField(..., min_length=12, max_length=72)

    @field_validator("new_password", mode="after")
    @classmethod
    def _check_byte_limit(cls, v: str) -> str:
        return _reject_over_72_bytes(v)


class DeploymentLimitRequest(BaseModel):
    deployment_limit: int = PydanticField(..., ge=1, le=500)


class GlobalMutationIntervalRequest(BaseModel):
    global_mutation_interval: str = PydanticField(..., pattern=r"^[1-9]\d*[mdMyY]$")


class UserResponse(BaseModel):
    uuid: str
    username: str
    role: str
    must_change_password: bool


class ConfigResponse(BaseModel):
    role: str
    deployment_limit: int
    global_mutation_interval: str


class AdminConfigResponse(ConfigResponse):
    users: List[UserResponse]
