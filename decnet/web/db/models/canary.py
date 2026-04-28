"""Canary token tables + CRUD DTOs.

Canary tokens are decoy artifacts (operator-uploaded honeydocs / synthesised
fake configs) planted inside a decky's filesystem.  When an attacker exfils
the artifact and uses it, an HTTP slug or DNS subdomain encoded into the
file is hit; the ``decnet canary`` worker observes the callback and
publishes ``canary.{token_id}.triggered`` on the bus.  The webhook fanout
+ correlator pick it up the same way they handle any other attacker
event — no canary-specific consumer wiring needed downstream.

Three tables:

* :class:`CanaryBlob` — operator-uploaded source artifact, deduped by
  sha256.  The original bytes live on disk under
  ``/var/lib/decnet/canary/blobs/{sha256}``; this row carries metadata
  + refcount-aware deletion.
* :class:`CanaryToken` — one planted artifact in one decky.  Either
  references a blob (``blob_id``) and an instrumenter, or is a wholly
  synthesised fake (e.g. ``aws_creds`` / ``git_config`` from a
  generator) and ``blob_id`` is NULL.  ``callback_token`` is the short
  random slug embedded into HTTP URLs and DNS labels — unique across
  the fleet so the worker can resolve a hit to a row in one query.
* :class:`CanaryTrigger` — append-only log of every callback hit.
  ``attacker_id`` is back-filled by the correlator after it attributes
  ``src_ip`` to an existing :class:`Attacker`; NULL until then.

We follow the project convention from :mod:`webhooks` and
:mod:`orchestrator`: stringly-typed UUIDs (``str`` PKs via
``str(uuid4())``), no FK to the composite-PK fleet table, indexes on
the join keys.  Pydantic request/response shapes live in this same
file (per :mod:`feedback_models_single_source`).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field as PydanticField
from sqlalchemy import Column, Index, Text
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


# --- Enum-shaped string literals -------------------------------------------

CanaryKind = Literal["http", "dns", "aws_passive"]
"""Detection mechanism for a token.

* ``http`` — slug embedded in artifact; attacker fetches our HTTP endpoint.
* ``dns`` — subdomain embedded; attacker's resolver looks up our DNS server.
* ``aws_passive`` — fake AWS credentials with no callback wiring.  Trips
  zero alerts on its own; useful only as bait + as evidence the attacker
  read the file when correlated with other timing signals.
"""

CanaryState = Literal["planted", "revoked", "failed"]
"""Lifecycle state of a token row.

* ``planted`` — file is in the decky and the slug/host is live.
* ``revoked`` — operator deleted the token; planter unlinked the file
  (best-effort) and the slug/host stops resolving.
* ``failed`` — placement failed (docker exec error, instrumenter
  rejected the blob, etc.); surfaced in the UI so the operator can
  retry or pick a different kind.
"""


# --- DB tables -------------------------------------------------------------

class CanaryBlob(SQLModel, table=True):
    """Operator-uploaded source artifact, deduped by sha256.

    The same bytes uploaded twice produce the same row (insert-or-get
    semantics in the repository).  We never store the bytes inline —
    only the disk path derived from ``sha256``.  Deletion is
    refcount-aware: ``DELETE`` is rejected while at least one
    :class:`CanaryToken` references the blob.
    """
    __tablename__ = "canary_blobs"

    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    sha256: str = Field(index=True, unique=True)
    filename: str  # original filename — UI display only, not used for path resolution
    content_type: str  # sniffed MIME (python-magic); drives instrumenter selection
    size_bytes: int
    uploaded_by: str = Field(index=True)  # User.uuid
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CanaryToken(SQLModel, table=True):
    """One canary artifact planted inside one decky."""
    __tablename__ = "canary_tokens"
    __table_args__ = (
        Index("ix_canary_tokens_decky", "decky_name", "state"),
    )

    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    kind: str = Field(index=True)  # CanaryKind literal at the API layer
    decky_name: str = Field(index=True)  # FleetDecky.name; no FK (composite PK)
    blob_uuid: Optional[str] = Field(
        default=None, foreign_key="canary_blobs.uuid", index=True,
    )
    # Which instrumenter mutated the blob (``docx``/``xlsx``/``pdf``/``html``/
    # ``image``/``plain``/``passthrough``).  NULL when the artifact came
    # from a synthesizer (``git_config``/``env_file``/``ssh_key``/
    # ``aws_creds``/``honeydoc``); ``generator`` carries that name instead.
    instrumenter: Optional[str] = Field(default=None)
    generator: Optional[str] = Field(default=None)
    placement_path: str  # absolute path inside the container
    # Short random slug (e.g. 16 url-safe bytes).  Embedded in HTTP URLs
    # *and* DNS labels — same value, different envelope, so both
    # detection paths resolve to the same token row.
    callback_token: str = Field(unique=True, index=True)
    # Stable secret used by re-instrumentation: same blob + same seed
    # = same mutated bytes, so re-seeding produces the same on-disk
    # artifact and the planter is naturally idempotent.
    secret_seed: str
    placed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered_at: Optional[datetime] = Field(default=None, index=True)
    trigger_count: int = Field(default=0)
    created_by: str = Field(index=True)  # User.uuid; "system" for baseline-seeded tokens
    state: str = Field(default="planted", index=True)
    last_error: Optional[str] = Field(
        default=None, sa_column=Column("last_error", Text, nullable=True),
    )


class CanaryTrigger(SQLModel, table=True):
    """Append-only log of one callback hit."""
    __tablename__ = "canary_triggers"
    __table_args__ = (
        Index("ix_canary_triggers_token_ts", "token_uuid", "occurred_at"),
        Index("ix_canary_triggers_attacker", "attacker_id"),
    )

    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    token_uuid: str = Field(foreign_key="canary_tokens.uuid", index=True)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str = Field(index=True)
    user_agent: Optional[str] = None
    request_path: Optional[str] = None  # HTTP path including the slug
    dns_qname: Optional[str] = None  # DNS qname when the hit came over DNS
    # JSON-encoded request headers (HTTP) or empty for DNS.  Stored as
    # TEXT for cross-dialect portability — same trick as
    # :attr:`WebhookSubscription.topic_patterns`.
    raw_headers: str = Field(
        default="{}",
        sa_column=Column("raw_headers", _BIG_TEXT, nullable=False, default="{}"),
    )
    # Set by the correlator once it attributes ``src_ip`` to an existing
    # :class:`Attacker`.  NULL until correlation runs (which happens on
    # the bus event we publish, so latency is sub-second).
    attacker_id: Optional[str] = Field(default=None, index=True)

    def headers(self) -> dict[str, Any]:
        """Decode :attr:`raw_headers` JSON; ``{}`` on bad/empty input."""
        try:
            raw = json.loads(self.raw_headers or "{}")
        except (ValueError, TypeError):
            return {}
        return raw if isinstance(raw, dict) else {}


# --- API request / response shapes -----------------------------------------

class CanaryBlobResponse(BaseModel):
    uuid: str
    sha256: str
    filename: str
    content_type: str
    size_bytes: int
    uploaded_by: str
    uploaded_at: datetime
    # Number of tokens currently referencing this blob.  Surfaces in the
    # UI so operators don't try to delete a blob that's still in use,
    # and the API uses it to gate ``DELETE`` (returns 409).
    token_count: int = 0


class CanaryTokenCreateRequest(BaseModel):
    """Generate + plant a new token.

    Exactly one of ``blob_uuid`` (operator-supplied artifact) or
    ``generator`` (synthesised fake) must be set.  Validated in the
    router so the 400 carries a clear detail message.
    """
    decky_name: str = PydanticField(..., min_length=1)
    kind: CanaryKind
    placement_path: str = PydanticField(..., min_length=1)
    blob_uuid: Optional[str] = None
    generator: Optional[str] = None  # git_config | env_file | ssh_key | aws_creds | honeydoc
    # Optional override for the path-mapping helper — useful when the
    # operator wants a specific Windows-shaped path on a windows-persona
    # decky.  Defaults to placement_path verbatim.
    persona_path_hint: Optional[str] = None


class CanaryTokenResponse(BaseModel):
    uuid: str
    kind: CanaryKind
    decky_name: str
    blob_uuid: Optional[str]
    instrumenter: Optional[str]
    generator: Optional[str]
    placement_path: str
    callback_token: str
    placed_at: datetime
    last_triggered_at: Optional[datetime]
    trigger_count: int
    created_by: str
    state: CanaryState
    last_error: Optional[str]


class CanaryTriggerResponse(BaseModel):
    uuid: str
    token_uuid: str
    occurred_at: datetime
    src_ip: str
    user_agent: Optional[str]
    request_path: Optional[str]
    dns_qname: Optional[str]
    headers: dict[str, Any] = PydanticField(default_factory=dict)
    attacker_id: Optional[str]


class CanaryTokensResponse(BaseModel):
    tokens: List[CanaryTokenResponse]
    total: int


class CanaryTriggersResponse(BaseModel):
    triggers: List[CanaryTriggerResponse]
    total: int


class CanaryBlobsResponse(BaseModel):
    blobs: List[CanaryBlobResponse]
    total: int
