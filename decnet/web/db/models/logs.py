"""Log / Bounty / State tables + their list-response DTOs."""
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel
from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


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
    # OTEL trace context — bridges the collector→ingester trace to the SSE
    # read path.  Nullable so pre-existing rows and non-traced deployments
    # are unaffected.
    trace_id: Optional[str] = Field(default=None)
    span_id: Optional[str] = Field(default=None)


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
