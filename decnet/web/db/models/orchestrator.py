"""Orchestrator-emitted activity events.

Purpose-built sibling to ``logs.Log`` so attacker-originated events stay
cleanly separable from synthetic life-injection events at query time.
The orchestrator worker is the sole writer.
"""
from datetime import datetime, timezone
from typing import Any, List, Optional
from uuid import uuid4

from pydantic import BaseModel
from sqlalchemy import Column, Index, Text
from sqlmodel import Field, SQLModel


class OrchestratorEvent(SQLModel, table=True):
    """One orchestrator-driven action against a decky.

    ``kind`` discriminates the two MVP flavours:

    * ``"traffic"`` — a protocol-driven interaction (SSH command exec for
      MVP). ``src_decky_uuid`` is the *logical* originator and may differ
      from the actual TCP source for the duration of the MVP, where the
      orchestrator process drives the connection from the host. ``v1``
      will execute the connection from inside the source container.
    * ``"file"``  — a filesystem touch via ``docker exec`` against the
      destination decky. ``src_decky_uuid`` is null.

    ``payload`` is the per-action JSON envelope: command run, exit code,
    stdout/stderr digest, file path, byte counts, etc. Schema is
    deliberately loose — the worker can extend it without a migration.
    """
    __tablename__ = "orchestrator_events"
    __table_args__ = (
        Index("ix_orchestrator_events_dst_ts", "dst_decky_uuid", "ts"),
    )
    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    ts: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    kind: str = Field(index=True, max_length=16)              # traffic|file
    protocol: str = Field(index=True, max_length=16)          # ssh for MVP
    action: str = Field(max_length=64)                         # exec:uptime|file:create|...
    # No FK to topology_deckies: dst/src may be a TopologyDecky.uuid
    # (MazeNET source), a "host_uuid:name" composite (fleet / SWARM shard
    # sources), or — for retired deckies — a row that's already gone.  The
    # column is an opaque identifier matching whatever
    # ``BaseRepository.list_running_deckies`` emits in its ``uuid`` field.
    # Index is kept; the FK was misleading and broke fleet-source events.
    src_decky_uuid: Optional[str] = Field(default=None, index=True)
    dst_decky_uuid: str = Field(index=True)
    success: bool = Field(default=False, index=True)
    payload: str = Field(
        sa_column=Column("payload", Text, nullable=False, default="{}")
    )


class OrchestratorEventsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]
