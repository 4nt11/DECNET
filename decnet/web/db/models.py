from datetime import datetime, timezone
from typing import Optional, Any, List
from sqlmodel import SQLModel, Field
from pydantic import BaseModel, Field as PydanticField

# --- Database Tables (SQLModel) ---

class User(SQLModel, table=True):
    __tablename__ = "users"
    uuid: str = Field(primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: str = Field(default="viewer")
    must_change_password: bool = Field(default=False)

class Log(SQLModel, table=True):
    __tablename__ = "logs"
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    decky: str = Field(index=True)
    service: str = Field(index=True)
    event_type: str = Field(index=True)
    attacker_ip: str = Field(index=True)
    raw_line: str
    fields: str 
    msg: Optional[str] = None

class Bounty(SQLModel, table=True):
    __tablename__ = "bounty"
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    decky: str = Field(index=True)
    service: str = Field(index=True)
    attacker_ip: str = Field(index=True)
    bounty_type: str = Field(index=True)
    payload: str

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

class LogsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]

class BountyResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]

class StatsResponse(BaseModel):
    total_logs: int
    unique_attackers: int
    active_deckies: int
    deployed_deckies: int

class MutateIntervalRequest(BaseModel):
    mutate_interval: Optional[int] = None

class DeployIniRequest(BaseModel):
    ini_content: str = PydanticField(..., min_length=5, max_length=512 * 1024)
