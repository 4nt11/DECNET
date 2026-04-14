from datetime import datetime, timezone
from typing import Optional, Any, List, Annotated
from sqlmodel import SQLModel, Field
from pydantic import BaseModel, ConfigDict, Field as PydanticField, BeforeValidator
from decnet.models import IniContent

def _normalize_null(v: Any) -> Any:
    if isinstance(v, str) and v.lower() in ("null", "undefined", ""):
        return None
    return v

NullableDatetime = Annotated[Optional[datetime], BeforeValidator(_normalize_null)]
NullableString = Annotated[Optional[str], BeforeValidator(_normalize_null)]

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


class State(SQLModel, table=True):
    __tablename__ = "state"
    key: str = Field(primary_key=True)
    value: str  # Stores JSON serialized DecnetConfig or other state blobs


class Attacker(SQLModel, table=True):
    __tablename__ = "attackers"
    ip: str = Field(primary_key=True)
    first_seen: datetime = Field(index=True)
    last_seen: datetime = Field(index=True)
    event_count: int = Field(default=0)
    service_count: int = Field(default=0)
    decky_count: int = Field(default=0)
    services: str = Field(default="[]")       # JSON list[str]
    deckies: str = Field(default="[]")        # JSON list[str], first-contact ordered
    traversal_path: Optional[str] = None      # "decky-01 → decky-03 → decky-05"
    is_traversal: bool = Field(default=False)
    bounty_count: int = Field(default=0)
    credential_count: int = Field(default=0)
    fingerprints: str = Field(default="[]")   # JSON list[dict] — bounty fingerprints
    commands: str = Field(default="[]")       # JSON list[dict] — commands per service/decky
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )

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

class AttackersResponse(BaseModel):
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
    # Human-readable duration: <number><unit> where unit is m(inutes), d(ays), M(onths), y/Y(ears).
    # Minimum granularity is 1 minute. Seconds are not accepted.
    mutate_interval: Optional[str] = PydanticField(None, pattern=r"^[1-9]\d*[mdMyY]$")

class DeployIniRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # This field now enforces strict INI structure during Pydantic initialization.
    # The OpenAPI schema correctly shows it as a required string.
    ini_content: IniContent = PydanticField(..., description="A valid INI formatted string")
