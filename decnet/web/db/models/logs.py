# SPDX-License-Identifier: AGPL-3.0-or-later
"""Log / Bounty / Credential / State tables + their list-response DTOs."""
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel
from sqlalchemy import Column, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


class Log(SQLModel, table=True):
    __tablename__ = "logs"
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    decky: str = Field(index=True)
    service: str = Field(index=True)
    event_type: str = Field(index=True)
    attacker_ip: str = Field(index=True)
    # Long-text columns — use TEXT so MySQL DDL doesn't truncate to VARCHAR(255).
    # TEXT is equivalent to plain text in SQLite.
    raw_line: str = Field(sa_column=Column("raw_line", Text, nullable=False))
    fields: str = Field(sa_column=Column("fields", Text, nullable=False))
    msg: Optional[str] = Field(default=None, sa_column=Column("msg", Text, nullable=True))
    # OTEL trace context — bridges the collector→ingester trace to the SSE
    # read path.  Nullable so pre-existing rows and non-traced deployments
    # are unaffected.
    trace_id: Optional[str] = Field(default=None)
    span_id: Optional[str] = Field(default=None)


class Bounty(SQLModel, table=True):
    __tablename__ = "bounty"
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    decky: str = Field(index=True)
    service: str = Field(index=True)
    attacker_ip: str = Field(index=True)
    bounty_type: str = Field(index=True)
    payload: str = Field(sa_column=Column("payload", Text, nullable=False))


class Credential(SQLModel, table=True):
    """One observed credential attempt against a decky service.

    Forward-compatible across every auth-bearing service in the fleet:
    SSH user+pass, Telnet user+pass, SMTP domain+pass, LDAP dn+pass,
    Redis password-only, etc. The two universal lossless representations
    (``secret_b64`` + ``secret_sha256``) hoist to indexed columns so
    cross-service reuse queries don't scan opaque JSON.

    Per-service identity (the human-meaningful "who's authenticating")
    lives in ``principal`` — username for SSH, domain for SMTP, dn for
    LDAP. Nullable for principal-less mechanisms (Redis AUTH, bearer
    tokens). Fully service-specific keys ride in ``fields`` JSON.

    Dedup contract: same (attacker_ip, decky, service, secret_sha256,
    principal_or_empty) tuple → upsert, bumps ``attempt_count`` and
    ``last_seen``. Different secret or different principal → new row.

    ``attacker_uuid`` is backfilled by the profiler once an Attacker row
    has been minted for the source IP. It is nullable on first write so
    the credential ingest path stays decoupled from the profiler.
    """
    __tablename__ = "credentials"
    __table_args__ = (
        Index("ix_credentials_secret_service", "secret_sha256", "service"),
        Index("ix_credentials_principal_service", "principal", "service"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    # Keyed by attacker IP (not attackers.uuid) on the write path to
    # avoid the chicken-and-egg of landing a credential before the
    # profiler has minted the Attacker. The profiler backfills
    # ``attacker_uuid`` once it knows the IP, so cross-IP reuse queries
    # eventually have an indexed FK to traverse.
    attacker_ip: str = Field(index=True)
    attacker_uuid: Optional[str] = Field(
        default=None, foreign_key="attackers.uuid", index=True
    )
    decky_name: str = Field(index=True)
    service: str = Field(index=True)
    principal: Optional[str] = Field(default=None, index=True, max_length=256)
    # Discriminator for what `secret_b64` actually contains. Default
    # ``"plaintext"`` — a recoverable password the attacker sent on the
    # wire (SSH/Telnet/FTP/IMAP/POP3/SMTP/Redis/LDAP/MQTT). Other kinds:
    # ``"postgres_md5_challenge"`` (md5(md5(pw+user)+salt) hex bytes
    # the attacker sent in the Postgres password message — plaintext
    # irrecoverable), ``"vnc_des_response"`` (16-byte DES-encrypted
    # challenge response — same shape).
    #
    # Reuse semantics gracefully degrade: same secret_sha256 only
    # correlates within a single ``secret_kind``. Cross-kind matches
    # are meaningless because different challenges produce different
    # bytes for the same plaintext password.
    secret_kind: str = Field(default="plaintext", index=True, max_length=32)
    # Universal lossless secret representations. For non-plaintext
    # kinds, secret_b64 is base64 of the raw attacker-sent bytes (after
    # hex-decode for protocols that ship the response as a hex string).
    secret_sha256: str = Field(index=True, max_length=64)
    secret_b64: Optional[str] = Field(default=None, max_length=2048)
    # Best-effort printable form — non-printable bytes collapsed to '?'
    # by either auth-helper.c (SSH/Telnet) or the ingester's legacy
    # adapter (FTP/POP3/IMAP/SMTP). May be lossy on non-UTF8.
    secret_printable: Optional[str] = Field(default=None, max_length=512)
    outcome: Optional[str] = Field(default=None, max_length=16)  # success|failure|observed
    fields: str = Field(
        sa_column=Column("fields", _BIG_TEXT, nullable=False, default="{}")
    )
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    attempt_count: int = Field(default=1)


class CredentialReuse(SQLModel, table=True):
    """One observed credential reuse pattern across deckies and/or services.

    A row here is a *finding* produced by the correlator: the same
    ``(secret_sha256, secret_kind, principal)`` tuple was observed
    against ``target_count`` distinct decky×service pairs. Upserted on
    that natural key — the row accumulates new deckies/services/IPs
    over time as the credential is reused.

    The ``confidence`` column is reserved for a future fuzzy-match pass
    (credential variants, e.g. ``hunter2`` vs ``hunter22``); rows
    written by the exact-secret correlator are always 1.0.
    """
    __tablename__ = "credential_reuse"
    __table_args__ = (
        UniqueConstraint(
            "secret_sha256", "secret_kind", "principal_key",
            name="uq_credential_reuse_secret_principal",
        ),
    )
    id: str = Field(primary_key=True, max_length=36)
    secret_sha256: str = Field(index=True, max_length=64)
    secret_kind: str = Field(index=True, max_length=32)
    # Optional human-readable principal (e.g. "root"). Nullable — for
    # cross-principal reuse rows we leave this null, but we still need
    # a unique constraint, so ``principal_key`` is the non-null
    # canonicalised form ("" when principal is null) used in the
    # uniqueness tuple. SQLite's NULLs-distinct-in-UNIQUE behaviour
    # would otherwise let duplicate null-principal rows through.
    principal: Optional[str] = Field(default=None, max_length=256)
    principal_key: str = Field(default="", max_length=256)
    attacker_uuids: str = Field(
        default="[]",
        sa_column=Column("attacker_uuids", _BIG_TEXT, nullable=False, default="[]"),
    )  # JSON list[str]
    attacker_ips: str = Field(
        default="[]",
        sa_column=Column("attacker_ips", _BIG_TEXT, nullable=False, default="[]"),
    )  # JSON list[str]
    deckies: str = Field(
        default="[]",
        sa_column=Column("deckies", _BIG_TEXT, nullable=False, default="[]"),
    )  # JSON list[str]
    services: str = Field(
        default="[]",
        sa_column=Column("services", _BIG_TEXT, nullable=False, default="[]"),
    )  # JSON list[str]
    # COUNT(DISTINCT decky||':'||service). The discriminative scalar
    # for ranking and filtering — a credential seen on 12 targets is
    # far more interesting than one seen on 2.
    target_count: int = Field(default=0, index=True)
    attempt_count: int = Field(default=0)
    confidence: float = Field(default=1.0)
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )


class CredentialReuseResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]


class State(SQLModel, table=True):
    __tablename__ = "state"
    key: str = Field(primary_key=True)
    # JSON-serialized DecnetConfig or other state blobs — can be large as
    # deckies/services accumulate.  MEDIUMTEXT on MySQL (16 MiB ceiling).
    value: str = Field(sa_column=Column("value", _BIG_TEXT, nullable=False))


class LogsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]


class BountyResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]


class CredentialsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]


class StatsResponse(BaseModel):
    total_logs: int
    unique_attackers: int
    active_deckies: int
    deployed_deckies: int
