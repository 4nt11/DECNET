"""Realism — synthetic-file state across orchestrator ticks.

The orchestrator's pre-realism file generator forgot every file the
moment it was planted: each tick wrote a brand-new ``notes-{ts}.txt``
with a literal unix-epoch suffix.  No edits, no rotation, no diurnal
shape — three of the realism failures the migration is fixing.

:class:`SyntheticFile` is the per-(decky, path) memory that lets the
realism engine read back yesterday's ``TODO.md``, mutate it, write
back the new body, and let the dashboard inspect the lineage.

Pre-v1: schema lives directly in the SQLModel; no ``_migrate_*``
helper (per the project's "no new migrations pre-v1" rule —
``feedback_no_new_migrations_prev1.md``).  Alembic lands at v1.
"""
from datetime import datetime, timezone
from typing import Any, List
from uuid import uuid4

from pydantic import BaseModel
from sqlalchemy import Column, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel


SYNTHETIC_FILE_BODY_LIMIT = 65536
"""Cap on persisted ``synthetic_files.last_body`` bytes.

Enforced by the repo on both insert and update — callers may pass the
full body; the repo clips. Large blobs (DOCX/PDF, canary artifacts) are
wasted disk on the master side; the decky filesystem holds the canonical
bytes."""


class SyntheticFile(SQLModel, table=True):
    """One realism-planted file on one decky.

    The unique key is ``(decky_uuid, path)`` — there's at most one
    realism record per location, even if the planter has rotated the
    file (rotation updates ``edit_count`` and ``last_modified``, not
    a new row).

    ``last_body`` is capped — large blobs (DOCX/PDF, future canary
    artifacts) are truncated at write time.  The edit-in-place flow
    (stage 3b) only needs the body when the content class supports
    body-level mutation (``note``, ``todo``, ``draft``, ``script``),
    so storing the canonical bytes for binary blobs would be wasted.

    ``content_hash`` is sha256 of the *body bytes only* — never of
    metadata or wrapper headers — so a hash compare is a cheap
    "did the body change?" check across edits.
    """
    __tablename__ = "synthetic_files"
    __table_args__ = (
        UniqueConstraint(
            "decky_uuid", "path", name="uq_synthetic_files_decky_path",
        ),
        Index("ix_synthetic_files_decky_modified", "decky_uuid", "last_modified"),
    )
    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    decky_uuid: str = Field(index=True, max_length=64)
    path: str = Field(max_length=1024)
    persona: str = Field(max_length=128)              # EmailPersona.name
    content_class: str = Field(max_length=32, index=True)  # ContentClass enum value
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True,
    )
    last_modified: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    edit_count: int = Field(default=0)
    content_hash: str = Field(max_length=64)          # sha256 hex
    last_body: str = Field(
        sa_column=Column("last_body", Text, nullable=False, default="")
    )


class SyntheticFilesResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]
