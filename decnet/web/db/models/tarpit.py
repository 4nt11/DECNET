# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tarpit rule table + HTTP request/response shapes."""
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field as PydanticField
from sqlmodel import Field, SQLModel


class TarpitRule(SQLModel, table=True):
    """One active tarpit rule — one per decky at a time.

    ``ports`` is JSON-encoded (e.g. ``"[22, 80]"``).  One row per decky;
    ``set_tarpit_rule`` upserts on ``decky_name`` so re-enabling with
    different parameters replaces the old rule.
    """
    __tablename__ = "tarpit_rules"

    id: str = Field(primary_key=True)
    decky_name: str = Field(index=True, unique=True)
    ports: str          # JSON list[int]
    delay_ms: int
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_by: str     # operator UUID from JWT


class TarpitEnableRequest(BaseModel):
    ports: list[int] = PydanticField(..., min_length=1)
    delay_ms: int = PydanticField(..., ge=100, le=300_000)


class TarpitRuleResponse(BaseModel):
    id: str
    decky_name: str
    ports: list[int]
    delay_ms: int
    created_at: datetime
    created_by: str


class TarpitStatusResponse(BaseModel):
    rule: TarpitRuleResponse
    active_connections: list[dict[str, Any]]
