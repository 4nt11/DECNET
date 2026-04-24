"""Webhook subscription table + CRUD DTOs.

Webhooks push DECNET bus events out to external SIEM / SOAR stacks
(Wazuh, Shuffle, TheHive, n8n, ...). Each subscription carries a set
of NATS-style topic patterns; the `decnet webhook` worker subscribes
to the union of patterns across all enabled subscriptions and POSTs
matching events to each matching URL with HMAC-SHA256 signing.

Simple mode (UI) exposes a friendly enum (`AttackerDetail`,
`DeckyStatus`, `SystemStatus`) that expands to patterns at save time.
Advanced mode lets an admin set raw patterns directly. Storage is
always the expanded list — the enum is sugar at the router layer.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field as PydanticField, HttpUrl
from sqlmodel import Field, SQLModel


SimpleEvent = Literal["AttackerDetail", "DeckyStatus", "SystemStatus"]


class WebhookSubscription(SQLModel, table=True):
    __tablename__ = "webhook_subscriptions"

    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True, unique=True)
    url: str
    secret: str  # HMAC-SHA256 key; plaintext pre-v1 (see DEBT-037 §7)
    # JSON-encoded list[str] of NATS-style bus topic patterns.
    # Storing as TEXT keeps the schema portable across SQLite and MySQL
    # without pulling in dialect-specific JSON columns.
    topic_patterns: str = Field(default="[]")
    enabled: bool = Field(default=True, index=True)
    consecutive_failures: int = Field(default=0)
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def patterns(self) -> list[str]:
        """Decode `topic_patterns` to a list. Returns [] on bad/empty JSON."""
        try:
            raw = json.loads(self.topic_patterns or "[]")
        except (ValueError, TypeError):
            return []
        return [p for p in raw if isinstance(p, str)]


# --- API Request / Response Models (Pydantic) ---


class WebhookCreateRequest(BaseModel):
    name: str = PydanticField(..., min_length=1, max_length=64)
    url: HttpUrl
    # If secret is omitted, the router generates a secure random one and
    # returns it exactly once on the create response. After that, callers
    # can only rotate via PATCH.
    secret: Optional[str] = PydanticField(None, min_length=16, max_length=256)
    # At least one of simple_events / topic_patterns must be non-empty
    # (validated in the router, not Pydantic, so the 400 carries a clear
    # detail message).
    simple_events: List[SimpleEvent] = PydanticField(default_factory=list)
    topic_patterns: List[str] = PydanticField(default_factory=list)
    enabled: bool = True


class WebhookUpdateRequest(BaseModel):
    # Partial update — every field optional; the router diffs against the
    # current row and only writes what changed.
    name: Optional[str] = PydanticField(None, min_length=1, max_length=64)
    url: Optional[HttpUrl] = None
    secret: Optional[str] = PydanticField(None, min_length=16, max_length=256)
    simple_events: Optional[List[SimpleEvent]] = None
    topic_patterns: Optional[List[str]] = None
    enabled: Optional[bool] = None


class WebhookResponse(BaseModel):
    """Public shape — deliberately omits `secret`."""

    uuid: str
    name: str
    url: str
    topic_patterns: List[str]
    enabled: bool
    consecutive_failures: int
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class WebhookCreateResponse(WebhookResponse):
    """Create-path response — carries the secret exactly once, for copy-out."""

    secret: str


class WebhookTestResponse(BaseModel):
    delivered: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


def _row_to_response_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a DB row into the WebhookResponse dict shape.

    Used by the CRUD router to decode `topic_patterns` JSON and drop the
    `secret` column before returning to the client.
    """
    out = dict(row)
    raw = out.pop("topic_patterns", "[]")
    try:
        out["topic_patterns"] = json.loads(raw or "[]")
    except (ValueError, TypeError):
        out["topic_patterns"] = []
    out.pop("secret", None)
    return out
