# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-(identity, primitive) attribution state — v0 of the
attribution engine.

Materialised view of the state machine in
``decnet.correlation.attribution.aggregate``. Re-derivable from
``observations`` + the DEBT-032 fingerprint-rotation log; this row is
a cache for cheap dashboard reads, not a source of truth.

Keyed on ``identity_uuid``, not ``attacker_uuid``: pre-clusterer,
every Attacker maps 1:1 to a stub row in ``attacker_identities``
(``merged_into_uuid = NULL``) so the key is stable across the v0 / v1
boundary. When v1's clusterer eventually merges identities, the loser
row's state is recomputed from the union of observations under the
winner — no schema change, no column-rename migration.

This deviates from ``development/ATTRIBUTION-ENGINE.md`` §"Subject of
attribution in v0" (which resolved on ``attacker_uuid``); the doc gets
a deviation note in the same commit that ships this file.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column, Index
from sqlmodel import Field, SQLModel


class AttributionStateRow(SQLModel, table=True):
    """One state row per (identity, primitive). At most one row per
    pair — composite PK enforces it.
    """

    __tablename__ = "attribution_state"
    __table_args__ = (
        Index("ix_attribution_state_state", "state"),
        Index("ix_attribution_state_last_change", "last_change_ts"),
        Index(
            "ix_attribution_state_identity_state",
            "identity_uuid", "state",
        ),
    )

    # ── key ────────────────────────────────────────────────────────────
    identity_uuid: str = Field(
        foreign_key="attacker_identities.uuid", primary_key=True,
    )
    primitive: str = Field(primary_key=True)

    # ── derived state ──────────────────────────────────────────────────
    # Mirrors the BEHAVE Observation ``value`` column shape so the
    # frontend can render the merger output the same way it renders raw
    # latest-wins values today (BEHAVE-INTEGRATION.md Q3).
    current_value: dict[str, Any] | str | int | float | bool | list = Field(
        sa_column=Column(JSON, nullable=False),
    )
    # 'unknown' | 'stable' | 'drifting' | 'conflicted' | 'multi_actor'.
    # Five states, frozen — see ATTRIBUTION-ENGINE.md §"State machine".
    state: str
    # Engine's confidence in the *state assertion*, not in any verdict
    # about the attacker. ``multi_actor`` is capped at 0.6 by
    # convention; other states use the merger's per-ValueKind formula.
    confidence: float
    # How many observations underlie this row. Used by the API to gate
    # ``unknown`` (< 3 obs) without re-querying ``observations``.
    observation_count: int = Field(default=0)
    # When ``state`` last flipped. Equals ``updated_at`` on insert.
    last_change_ts: float
    # Most recent observation that fed this row. Used by the merger to
    # detect drift windows without a full observation re-scan.
    last_observation_ts: float

    # ── audit ──────────────────────────────────────────────────────────
    # Mirrors AttackerIdentity convention (federation gossip in v2).
    schema_version: int = Field(default=1)
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
