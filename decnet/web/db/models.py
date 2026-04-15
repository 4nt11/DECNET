from datetime import datetime, timezone
from typing import Literal, Optional, Any, List, Annotated
from sqlalchemy import Column, Text
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlmodel import SQLModel, Field

# Use on columns that accumulate over an attacker's lifetime (commands,
# fingerprints, state blobs).  TEXT on MySQL caps at 64 KiB; MEDIUMTEXT
# stretches to 16 MiB.  SQLite has no fixed-width text types so Text()
# stays unchanged there.
_BIG_TEXT = Text().with_variant(MEDIUMTEXT(), "mysql")
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
    # Long-text columns — use TEXT so MySQL DDL doesn't truncate to VARCHAR(255).
    # TEXT is equivalent to plain text in SQLite.
    raw_line: str = Field(sa_column=Column("raw_line", Text, nullable=False))
    fields: str = Field(sa_column=Column("fields", Text, nullable=False))
    msg: Optional[str] = Field(default=None, sa_column=Column("msg", Text, nullable=True))

class Bounty(SQLModel, table=True):
    __tablename__ = "bounty"
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    decky: str = Field(index=True)
    service: str = Field(index=True)
    attacker_ip: str = Field(index=True)
    bounty_type: str = Field(index=True)
    payload: str = Field(sa_column=Column("payload", Text, nullable=False))


class State(SQLModel, table=True):
    __tablename__ = "state"
    key: str = Field(primary_key=True)
    # JSON-serialized DecnetConfig or other state blobs — can be large as
    # deckies/services accumulate.  MEDIUMTEXT on MySQL (16 MiB ceiling).
    value: str = Field(sa_column=Column("value", _BIG_TEXT, nullable=False))


class Attacker(SQLModel, table=True):
    __tablename__ = "attackers"
    uuid: str = Field(primary_key=True)
    ip: str = Field(index=True)
    first_seen: datetime = Field(index=True)
    last_seen: datetime = Field(index=True)
    event_count: int = Field(default=0)
    service_count: int = Field(default=0)
    decky_count: int = Field(default=0)
    # JSON blobs — these grow over the attacker's lifetime.  Use MEDIUMTEXT on
    # MySQL (16 MiB) for the fields that accumulate (fingerprints, commands,
    # and the deckies/services lists that are unbounded in principle).
    services: str = Field(
        default="[]", sa_column=Column("services", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[str]
    deckies: str = Field(
        default="[]", sa_column=Column("deckies", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[str], first-contact ordered
    traversal_path: Optional[str] = Field(
        default=None, sa_column=Column("traversal_path", Text, nullable=True)
    )  # "decky-01 → decky-03 → decky-05"
    is_traversal: bool = Field(default=False)
    bounty_count: int = Field(default=0)
    credential_count: int = Field(default=0)
    fingerprints: str = Field(
        default="[]", sa_column=Column("fingerprints", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[dict] — bounty fingerprints
    commands: str = Field(
        default="[]", sa_column=Column("commands", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[dict] — commands per service/decky
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )


class AttackerBehavior(SQLModel, table=True):
    """
    Timing & behavioral profile for an attacker, joined to Attacker by uuid.

    Kept in a separate table so the core Attacker row stays narrow and
    behavior data can be updated independently (e.g. as the sniffer observes
    more packets) without touching the event-count aggregates.
    """
    __tablename__ = "attacker_behavior"
    attacker_uuid: str = Field(primary_key=True, foreign_key="attackers.uuid")
    # OS / TCP stack fingerprint (rolled up from sniffer events)
    os_guess: Optional[str] = None
    hop_distance: Optional[int] = None
    tcp_fingerprint: str = Field(
        default="{}",
        sa_column=Column("tcp_fingerprint", Text, nullable=False, default="{}"),
    )  # JSON: window, wscale, mss, options_sig
    retransmit_count: int = Field(default=0)
    # Behavioral (derived by the profiler from log-event timing)
    behavior_class: Optional[str] = None          # beaconing | interactive | scanning | brute_force | slow_scan | mixed | unknown
    beacon_interval_s: Optional[float] = None
    beacon_jitter_pct: Optional[float] = None
    tool_guesses: Optional[str] = None            # JSON list[str] — all matched tools
    timing_stats: str = Field(
        default="{}",
        sa_column=Column("timing_stats", Text, nullable=False, default="{}"),
    )  # JSON: mean/median/stdev/min/max IAT
    phase_sequence: str = Field(
        default="{}",
        sa_column=Column("phase_sequence", Text, nullable=False, default="{}"),
    )  # JSON: recon_end/exfil_start/latency
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


class ComponentHealth(BaseModel):
    status: Literal["ok", "failing"]
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    components: dict[str, ComponentHealth]
