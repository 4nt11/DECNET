# SPDX-License-Identifier: AGPL-3.0-or-later
"""Campaign — operation-level grouping of resolved attacker identities."""
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel
from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel


class Campaign(SQLModel, table=True):
    """
    Campaign — one operation, one or more identities.

    Sits one level above ``AttackerIdentity``: an actor (identity) may
    appear in multiple campaigns over time, and a campaign may have
    several distinct identities cooperating (e.g. a night-shift and
    day-shift operator on the same job — fixture F5 multi_operator).

    Populated by the campaign clusterer worker (downstream of identity
    resolution). Empty rows are valid; the table ships empty until the
    clusterer lands. ``schema_version`` is non-negotiable from day one
    for the same federation-gossip reason ``AttackerIdentity`` carries
    one — bumping campaign-level feature definitions without a version
    field silently poisons cross-operator gossip in V2.

    See ``development/CAMPAIGN_CLUSTERING.md`` for the signal taxonomy
    (phase-handoff, shared-infra, temporal overlap, cohort).
    """
    __tablename__ = "campaigns"
    uuid: str = Field(primary_key=True)
    schema_version: int = Field(default=1)
    first_seen_at: Optional[datetime] = Field(default=None, index=True)
    last_seen_at: Optional[datetime] = Field(default=None, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    # Campaign-cohesion score from the clusterer. Range [0, 1]; null
    # until the clusterer writes. Higher = more confident the linked
    # identities are part of the same operation.
    confidence: Optional[float] = Field(default=None)
    # Denormalized count of FK'd ``AttackerIdentity`` rows.
    identity_count: int = Field(default=0)
    # Aggregated fingerprint summary across member identities. Same
    # JSON-serialized list[str] in TEXT shape as
    # ``AttackerIdentity.{ja3,hassh,payload_simhashes,c2_endpoints}`` —
    # federation gossip wants the same wire shape at every layer.
    ja3_hashes: Optional[str] = Field(
        default=None, sa_column=Column("ja3_hashes", Text, nullable=True)
    )
    hassh_hashes: Optional[str] = Field(
        default=None, sa_column=Column("hassh_hashes", Text, nullable=True)
    )
    tls_cert_sha256: Optional[str] = Field(
        default=None, sa_column=Column("tls_cert_sha256", Text, nullable=True)
    )
    payload_simhashes: Optional[str] = Field(
        default=None, sa_column=Column("payload_simhashes", Text, nullable=True)
    )
    c2_endpoints: Optional[str] = Field(
        default=None, sa_column=Column("c2_endpoints", Text, nullable=True)
    )
    # Soft-merge audit trail — same revocable-merge pattern as
    # ``AttackerIdentity.merged_into_uuid``. When the clusterer
    # collapses two campaigns, the loser's row stays in place with this
    # set to the winner's UUID; resolvers follow the chain.
    merged_into_uuid: Optional[str] = Field(
        default=None, foreign_key="campaigns.uuid", index=True
    )
    # Operator-editable free-form notes — annotation surface for
    # human analysts ("APT-XX Q2 campaign", "matches CTI report 5678").
    notes: Optional[str] = Field(
        default=None, sa_column=Column("notes", Text, nullable=True)
    )


class CampaignsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]
