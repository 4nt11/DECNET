from typing import Any
from pydantic import BaseModel, Field

class Token(BaseModel):
    access_token: str
    token_type: str
    must_change_password: bool = False


class LoginRequest(BaseModel):
    username: str
    password: str = Field(..., max_length=72)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., max_length=72)
    new_password: str = Field(..., max_length=72)


class LogsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[dict[str, Any]]


class BountyResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[dict[str, Any]]


class StatsResponse(BaseModel):
    total_logs: int
    unique_attackers: int
    active_deckies: int
    deployed_deckies: int


class MutateIntervalRequest(BaseModel):
    mutate_interval: int | None


class DeployIniRequest(BaseModel):
    ini_content: str = Field(..., min_length=5, max_length=512 * 1024)
