# SPDX-License-Identifier: AGPL-3.0-or-later
"""Observed-attachment intel — purpose-built table for the per-hash
keyspace of attachments delivered by attackers.

DECNET is a honeypot **platform**, not a one-off appliance. Every
attachment SHA-256 that crosses a decky is itself an artifact: it
seeds future cross-attacker correlation ("same hash, multiple
unrelated attackers? cross-decky propagation?"), feeds the EmailLifter
R0046 ``mal_hash_match`` lane with provider-attributed verdicts at
observation time, and underwrites future federation work without
locking us into a particular outbound shape today.

Per the standing rule "new use cases get their own table with UUID
PK," this is its own table — NOT a column-bag on ``attacker_intel``
(which is IP-keyed; one hash can ride many IPs) or on the email rows
(one hash can ride many emails; the cross-correlation question is
per-hash).
"""
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import JSON, Column, Index
from sqlmodel import Field, SQLModel


class ObservedAttachment(SQLModel, table=True):
    """One distinct file-attachment hash observed across the fleet.

    The natural key is ``sha256``; the row is upserted per observation
    via :meth:`BaseRepository.upsert_observed_attachment`. ``uuid`` is
    the surrogate PK — the ingester never refers to it directly, but
    future API surfaces benefit from the indirection (and from a
    UUID-shaped foreign-key column once federation work lands).
    """
    __tablename__ = "observed_attachments"
    __table_args__ = (
        Index("ix_observed_attachments_first_seen", "first_seen"),
        Index("ix_observed_attachments_last_seen", "last_seen"),
        Index("ix_observed_attachments_mal_hash_match", "mal_hash_match"),
    )

    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    sha256: str = Field(unique=True, index=True, max_length=64)

    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    observation_count: int = Field(default=1)

    first_seen_decky_uuid: Optional[str] = Field(default=None, index=True)
    first_seen_attacker_uuid: Optional[str] = Field(default=None, index=True)
    last_seen_attacker_uuid: Optional[str] = Field(default=None, index=True)

    # Native JSON list[str] — every distinct file extension this hash has
    # been delivered as. One hash, multiple extensions = obfuscation
    # signal worth keeping. Per the standing typed-evidence rule:
    # default_factory, not default=[].
    extensions: List[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, default=list),
    )
    first_subject: Optional[str] = Field(default=None)

    # Verdict captured at observation time. ``None`` = no provider has
    # classified yet. ``True`` is sticky — once any provider says
    # "known bad," subsequent ``None``/``False`` observations don't
    # downgrade the verdict (a hash a feed later forgets is still a
    # hash that feed once flagged).
    mal_hash_match: Optional[bool] = Field(default=None)
    mal_hash_match_provider: Optional[str] = Field(
        default=None, max_length=64,
    )
    mal_hash_match_at: Optional[datetime] = Field(default=None)
