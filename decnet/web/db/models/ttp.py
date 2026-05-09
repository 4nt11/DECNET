"""TTP-tagging schema — `ttp_tag`, `ttp_rule`, `ttp_rule_state`.

Contract step E.1.1 of `development/TTP_TAGGING.md`. Shapes only — no
behavior. Bus topics, ABCs, factories, RuleEngine, lifters, API, repo,
RuleStore land in subsequent contract commits and import from here.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional, TypedDict

from pydantic import BaseModel
from sqlalchemy import JSON, CheckConstraint, Column, Index
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


# Fixed namespace for `compute_tag_uuid()`. Derived once from the URL
# namespace + the literal label "decnet:ttp_tag:v1" so every process
# arrives at the same UUID. Pinned golden value is asserted in
# E.2.2 — DO NOT regenerate it; that would silently break replay
# safety for every existing tag UUID. The label in the comment is the
# input; the constant below is the resulting namespace UUID.
_TTP_TAG_NS: _uuid.UUID = _uuid.uuid5(_uuid.NAMESPACE_URL, "decnet:ttp_tag:v1")


def compute_tag_uuid(
    source_kind: str,
    source_id: str,
    rule_id: str,
    rule_version: int,
    technique_id: str,
    sub_technique_id: Optional[str],
) -> str:
    """Deterministic UUIDv5 over the tag-identity tuple.

    Inputs are EXACTLY the six fields enumerated in the parameter list
    — `(source_kind, source_id, rule_id, rule_version, technique_id,
    sub_technique_id)`. Adding `created_at`, a process PID, a random
    salt, or any other non-deterministic input breaks replay safety:
    the worker re-processing the same source events would write
    duplicate rows on every run. The CDD test in E.2.2 introspects
    this signature; a contributor must update that test deliberately
    to change the input set.
    """
    key = "|".join([
        source_kind,
        source_id,
        rule_id,
        str(rule_version),
        technique_id,
        sub_technique_id or "",
    ])
    return str(_uuid.uuid5(_TTP_TAG_NS, key))


# ── Evidence shape contract ─────────────────────────────────────────
# One TypedDict per `source_kind` carried in `TTPTag.evidence`. Adding
# a new `source_kind` means adding a TypedDict here AND a parametrized
# entry in `tests/ttp/test_evidence_shape.py`. The PII discipline
# from the design doc lives in the *type*: `EmailEvidence` has no
# field accommodating raw rcpt addresses or body bytes, so a lifter
# attempting to leak them fails type-check before it can run.

class CommandEvidence(TypedDict):
    matched_tokens: list[str]
    rule_pattern: str  # regex source string, never user input


class IntelEvidence(TypedDict):
    intel_uuid: str
    provider: Literal["abuseipdb", "greynoise", "feodo", "threatfox"]
    category: Optional[int]
    score: float  # already normalized to [0.0, 1.0]


class EmailEvidence(TypedDict):
    body_sha256: str  # hash, never raw body
    matched_headers: list[str]  # header NAMES, not values
    rcpt_domain_set: list[str]  # domains, not addresses
    attachment_sha256s: list[str]
    rcpt_count: int


class CanaryFingerprintEvidence(TypedDict):
    metric: str  # "navigator_webdriver", "canvas_hash", …
    matched_signature: str  # signature ID, not raw fingerprint blob


# ── Tables ──────────────────────────────────────────────────────────


class TTPTag(SQLModel, table=True):
    """One row per (source-event × MITRE technique × rule)."""

    __tablename__ = "ttp_tag"

    # RFC-4122 UUIDv5 string, deterministic over
    # (source_kind, source_id, rule_id, rule_version, technique_id,
    # sub_technique_id) under `_TTP_TAG_NS`. See `compute_tag_uuid()`.
    uuid: str = Field(primary_key=True)

    # Provenance — discriminator + opaque ID. No FK on `source_id`
    # because `source_kind` varies (see design doc "No FK on
    # source_id" + "Retention: tags outlive sources").
    source_kind: str
    source_id: str

    # Scope anchors. CHECK constraint requires at least one set.
    attacker_uuid: Optional[str] = Field(
        default=None,
        foreign_key="attackers.uuid",
        index=True,
        ondelete="CASCADE",
    )
    identity_uuid: Optional[str] = Field(
        default=None,
        foreign_key="attacker_identities.uuid",
        index=True,
        ondelete="CASCADE",
    )
    session_id: Optional[str] = Field(default=None, index=True)
    decky_id: Optional[str] = Field(default=None, index=True)

    # ATT&CK
    tactic: str = Field(index=True)  # "TA0001".."TA0043" / ICS range
    technique_id: str = Field(index=True)  # "T1110"
    sub_technique_id: Optional[str] = Field(default=None, index=True)

    # Confidence + evidence
    confidence: float
    rule_id: str = Field(index=True)
    rule_version: int

    # Native JSON column, dialect-adaptive (SQLite TEXT, MySQL JSON).
    # No `default=`; every insert MUST supply evidence. Per-source_kind
    # shape is pinned by the TypedDicts above and tested in E.2.1b.
    evidence: dict[str, Any] = Field(
        sa_column=Column(JSON, nullable=False),
    )

    # ATT&CK matrix release the tag was emitted against. REQUIRED —
    # technique IDs migrate between releases; a tag without a release
    # ID cannot render deterministically in MITRE Navigator.
    attack_release: str = Field(index=True)

    # Canonical attack.mitre.org URL for this technique (or
    # sub-technique when present). Resolved at insert via
    # decnet.ttp.attack_stix.mitre_url_for from the loaded STIX
    # bundle. Nullable because (a) the bundle may not be loaded in
    # certain test paths and (b) a future release could deprecate
    # a technique we have legacy tags for. Not indexed — derived
    # deeplink, not a query target; technique_id is already indexed.
    mitre_url: Optional[str] = Field(default=None)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        # MySQL <8.0.16 parses CHECK but does not enforce it; the
        # __init__ guard below covers that gap.
        CheckConstraint(
            "attacker_uuid IS NOT NULL OR identity_uuid IS NOT NULL",
            name="ttp_tag_has_anchor",
        ),
        Index(
            "ix_ttp_tag_identity_technique",
            "identity_uuid",
            "technique_id",
        ),
        Index(
            "ix_ttp_tag_attacker_technique",
            "attacker_uuid",
            "technique_id",
        ),
        Index(
            "ix_ttp_tag_technique_created",
            "technique_id",
            "created_at",
        ),
    )

    def __init__(self, **kwargs: Any) -> None:
        # Belt-and-braces for MySQL <8.0.16 where CHECK is silently
        # ignored. This guard runs BEFORE super().__init__() — i.e.
        # before Pydantic field validation — so the failure surfaces
        # as a plain `ValueError` with both anchor names in the
        # message, not as a generic `ValidationError`. The CDD test
        # in E.2.1 introspects this ordering and asserts the message
        # contains both substrings; do not "simplify" into a
        # `@field_validator` or generic `assert`.
        if (
            kwargs.get("attacker_uuid") is None
            and kwargs.get("identity_uuid") is None
        ):
            raise ValueError(
                "ttp_tag requires at least one of attacker_uuid / "
                "identity_uuid; both NULL is not a valid anchor."
            )
        super().__init__(**kwargs)


class TTPRule(SQLModel, table=True):
    """Rule definition mirror — populated by DatabaseRuleStore from
    on-disk YAML; FilesystemRuleStore reads disk directly and never
    writes here. One row per rule_id."""

    __tablename__ = "ttp_rule"

    rule_id: str = Field(primary_key=True)
    rule_version: int
    source_path: str
    yaml_content: str = Field(
        sa_column=Column("yaml_content", _BIG_TEXT, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    # Operator who pushed the edit. "filesystem" / "git" for the FS
    # store, the admin JWT subject for the DB store.
    updated_by: str


class TTPRuleState(SQLModel, table=True):
    """Operational state for a rule (enabled / disabled / clipped).

    Separate from TTPRule because state has fast lifecycle (operator
    hits a disable button) while definition has slow lifecycle (git
    commit + review). The engine merges (definition, state) at
    compile time.
    """

    __tablename__ = "ttp_rule_state"

    rule_id: str = Field(primary_key=True)
    state: str  # "enabled" | "disabled" | "clipped"
    confidence_max: Optional[float] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)
    reason: Optional[str] = Field(default=None)
    set_by: Optional[str] = Field(default=None)
    set_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


# ── API response models (Pydantic) ──────────────────────────────────
# Routed by `decnet/web/router/ttp/`. Per the project's "all models in
# models.py" rule these live here alongside the SQLModel tables, not
# in a sibling schemas.py. Empty-list returns at contract phase are
# typed against these models so the OpenAPI shape is stable from day
# one. See TTP_TAGGING.md §E.1.9.

class TechniqueRollupRow(BaseModel):
    """One row of /api/v1/ttp/techniques — distinct technique observed
    across the fleet with a count and a most-recent-seen timestamp."""

    technique_id: str
    technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    tactic: str
    count: int
    last_seen: datetime
    mitre_url: Optional[str] = None


class IdentityTechniqueRow(BaseModel):
    """One row of the by-identity / by-attacker / by-session endpoints —
    a distinct (technique, sub_technique) tuple within the requested
    scope, with an aggregate count and first/last-seen timestamps.

    ``technique_name`` / ``sub_technique_name`` come from
    :mod:`decnet.ttp.attack_catalog` (canonical ATT&CK labels for the
    pinned release). ``None`` when the ID isn't in the catalogue —
    the UI falls back to showing the bare ID.
    """

    technique_id: str
    technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    tactic: str
    count: int
    first_seen: datetime
    last_seen: datetime
    confidence_max: float
    mitre_url: Optional[str] = None


class TTPTagDetailRow(BaseModel):
    """One row of ``GET /api/v1/ttp/tags/by-{scope}/{uuid}/{technique_id}`` —
    a single ``ttp_tag`` row exposing the rule-engine's reasoning
    (rule_id / source_kind / source_id / evidence) so the operator UI
    can show *why* the engine flagged a technique, not just *that* it
    did. Mirrors the persisted shape of :class:`TTPTag` minus the
    NULL-anchor guard fields the consumer doesn't need."""

    uuid: str
    source_kind: str
    source_id: str
    attacker_uuid: Optional[str] = None
    identity_uuid: Optional[str] = None
    session_id: Optional[str] = None
    decky_id: Optional[str] = None
    tactic: str
    technique_id: str
    technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    confidence: float
    rule_id: str
    rule_version: int
    evidence: dict[str, Any] = Field(default_factory=dict)
    attack_release: str
    created_at: datetime
    mitre_url: Optional[str] = None


class CampaignTechniqueRow(BaseModel):
    """One row of /api/v1/ttp/by-campaign/{uuid} — a technique observed
    across at least one Identity rolled up into the campaign."""

    technique_id: str
    technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    tactic: str
    count: int
    identity_count: int
    last_seen: datetime
    mitre_url: Optional[str] = None


class RuleCatalogueRow(BaseModel):
    """One row of /api/v1/ttp/rules — a rule definition + its current
    operational state. The operator-facing rule list."""

    rule_id: str
    rule_version: int
    name: str
    description: str
    state: Literal["enabled", "disabled", "clipped"]
    confidence_max: Optional[float] = None
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
    set_by: Optional[str] = None
    set_at: Optional[datetime] = None


class RuleStateRequest(BaseModel):
    """POST /api/v1/ttp/rules/{rule_id}/state body — admin operator
    sets disable / clip / TTL on a rule. Pre-v1: schema is the public
    contract; downward changes require an OpenAPI version bump."""

    state: Literal["enabled", "disabled", "clipped"]
    confidence_max: Optional[float] = None
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None


class RuleStateResponse(BaseModel):
    """Response for POST/DELETE /api/v1/ttp/rules/{rule_id}/state and
    the per-rule entry of GET /rules. Mirrors :class:`TTPRuleState`."""

    rule_id: str
    state: Literal["enabled", "disabled", "clipped"]
    confidence_max: Optional[float] = None
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
    set_by: Optional[str] = None
    set_at: Optional[datetime] = None


class NavigatorTechnique(BaseModel):
    """Per-technique entry of the MITRE ATT&CK Navigator JSON layer."""

    techniqueID: str
    score: int
    color: str = ""
    comment: str = ""
    enabled: bool = True


class NavigatorLayer(BaseModel):
    """MITRE ATT&CK Navigator JSON layer envelope. Empty-but-valid at
    contract phase: a SOC analyst pasting this JSON into the official
    Navigator sees the file load cleanly with no highlighted
    techniques. See TTP_TAGGING.md §"UI surface — Empty state".
    """

    name: str = "DECNET TTP coverage"
    versions: dict[str, str] = Field(
        default_factory=lambda: {
            "attack": "15",
            "navigator": "5.1.0",
            "layer": "4.5",
        }
    )
    domain: str = "enterprise-attack"
    description: str = ""
    techniques: list[NavigatorTechnique] = Field(default_factory=list)
