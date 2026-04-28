"""Auth + user-management tables and DTOs."""
from typing import List, Literal

from pydantic import BaseModel, Field as PydanticField
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"
    uuid: str = Field(primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: str = Field(default="viewer")
    must_change_password: bool = Field(default=False)


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
    new_password: str = PydanticField(..., max_length=72)


# --- Configuration Models ---

class CreateUserRequest(BaseModel):
    username: str = PydanticField(..., min_length=1, max_length=64)
    password: str = PydanticField(..., min_length=8, max_length=72)
    role: Literal["admin", "viewer"] = "viewer"


class UpdateUserRoleRequest(BaseModel):
    role: Literal["admin", "viewer"]


class ResetUserPasswordRequest(BaseModel):
    new_password: str = PydanticField(..., min_length=8, max_length=72)


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
