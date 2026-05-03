"""BEHAVE-SHELL observation rows — generic table holding every
emitted Observation envelope.

Mirrors the BEHAVE-SHELL ``Observation`` Pydantic envelope
(``decnet_behave_core.spec.envelope.Observation``) field-for-field, plus
one DECNET-side denormalisation (``attacker_uuid``) for cheap joins.
The class is named ``ObservationRow`` to avoid colliding with the
BEHAVE Pydantic class when both are imported into the same module —
the Pydantic envelope is the wire format; this is the storage row.

See ``development/BEHAVE-INTEGRATION.md`` §"Storage" for the full
rationale.

Idempotency is enforced at the schema level by the
``UniqueConstraint(evidence_ref, primitive)`` index — re-running the
extractor on the same shard+sid produces a DB-side conflict that the
repo's upsert path resolves deterministically. ``evidence_ref`` is
NOT NULL for DECNET-emitted observations even though the BEHAVE
envelope makes it ``Optional[str]``: the worker's "have we already
profiled this session?" check keys on it, and the shape
``shard:{decky}/{service}/{date}.jsonl#sid`` is mandatory at the
worker layer.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Column, Index, UniqueConstraint
from sqlmodel import Field, SQLModel


class ObservationRow(SQLModel, table=True):
    """One BEHAVE-SHELL observation persisted to ``observations``.

    Re-derivable from the upstream session shard; this row is a cache
    for cheap dashboard reads, not the source of truth (which is the
    asciinema shard on disk + the BEHAVE-SHELL extractor).

    Type alignment with BEHAVE: ``id`` is a hex-string UUID (matching
    BEHAVE's ``Observation.id: str = Field(default_factory=lambda:
    uuid.uuid4().hex)``), not a typed UUID column. ``identity_ref``
    is ``str | None``, ditto.
    """

    __tablename__ = "observations"
    __table_args__ = (
        Index(
            "ix_observations_attacker_primitive_ts",
            "attacker_uuid", "primitive", "ts",
        ),
        Index("ix_observations_primitive_ts", "primitive", "ts"),
        UniqueConstraint(
            "evidence_ref", "primitive",
            name="uq_observations_evidence_primitive",
        ),
    )

    # ── envelope fields (types match BEHAVE exactly) ─────────────────────
    id: str = Field(primary_key=True)
    identity_ref: str | None = Field(default=None)
    primitive: str = Field(index=True)
    value: dict[str, Any] | str | int | float | bool | list = Field(
        sa_column=Column(JSON, nullable=False),
    )
    confidence: float
    window_start_ts: float
    window_end_ts: float
    source: str
    evidence_ref: str = Field(nullable=False)
    envelope_v: int
    ts: float = Field(index=True)

    # ── DECNET-side denormalisation (NOT in BEHAVE envelope) ─────────────
    # The envelope identifies the attacker via ``identity_ref`` once
    # attribution exists; pre-attribution, observations carry no
    # attacker linkage. DECNET resolves the (decky, service, sid, src_ip)
    # tuple to ``attacker_uuid`` at write time so AttackerDetail can
    # query without joining through the (still-empty)
    # ``attacker_identities`` table.
    attacker_uuid: str = Field(foreign_key="attackers.uuid", index=True)
