"""DeckyLifecycle table + DTOs.

Tracks one row per (decky, operation) attempt — `deploy` or `mutate` —
so the API can return 202 Accepted immediately and the wizard can poll
state instead of holding an open HTTP request open for minutes.

State machine: ``pending`` (row created, runner not yet started) →
``running`` (runner picked it up) → terminal ``succeeded`` | ``failed``
(+ ``error`` text).  Rows are immutable after terminal status; a retry
writes a new row.

Sibling of DeckyShard rather than a rework — DeckyShard tracks runtime
container state observed via heartbeat, this tracks operation lifecycle.
Per ``feedback_uuid_over_natural_keys``: new use case, new table, UUID PK.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field as PydanticField
from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

LifecycleOperation = Literal["deploy", "mutate"]
LifecycleStatus = Literal["pending", "running", "succeeded", "failed"]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class DeckyLifecycle(SQLModel, table=True):
    """One row per (decky, operation) attempt."""

    __tablename__ = "decky_lifecycle"

    id: str = Field(
        primary_key=True,
        default_factory=lambda: str(uuid.uuid4()),
    )
    decky_name: str = Field(index=True)
    # None for unihost / master-resident deckies.
    host_uuid: Optional[str] = Field(default=None, index=True)
    operation: str = Field(index=True)  # LifecycleOperation
    status: str = Field(default="pending", index=True)  # LifecycleStatus
    error: Optional[str] = Field(
        default=None, sa_column=Column("error", Text, nullable=True),
    )
    started_at: datetime = Field(default_factory=_now_utc)
    updated_at: datetime = Field(default_factory=_now_utc)
    completed_at: Optional[datetime] = Field(default=None)


# --- HTTP DTOs ---

class DeckyLifecycleView(BaseModel):
    """One lifecycle row, serialised for the wizard polling loop."""
    id: str
    decky_name: str
    host_uuid: Optional[str] = None
    operation: str
    status: str
    error: Optional[str] = None
    started_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None


class DeckyLifecycleListResponse(BaseModel):
    rows: list[DeckyLifecycleView] = PydanticField(default_factory=list)


class LifecycleAcceptedResponse(BaseModel):
    """Returned by 202 deploy/mutate endpoints — lets the client subscribe
    to the matching DeckyLifecycle rows via the polling endpoint."""
    lifecycle_ids: list[str]


class LifecycleDelta(BaseModel):
    """One per-decky completion record in a worker → master heartbeat."""
    decky_name: str
    operation: str
    status: str  # one of LifecycleStatus, typically "succeeded" | "failed"
    error: Optional[str] = None
    completed_at: Optional[datetime] = None
