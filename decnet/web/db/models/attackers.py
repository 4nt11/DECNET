"""Attacker core + per-attacker behavioral rows.

Per-session keystroke-dynamics fingerprints have moved out of this
module: the column-zoo ``SessionProfile`` shipped here pre-v0 was
superseded by the BEHAVE-SHELL ``observations`` table
(``decnet/web/db/models/observations.py``), which mirrors the BEHAVE
``Observation`` envelope and accepts every primitive the extractor
emits. See ``development/BEHAVE-INTEGRATION.md`` for the design and
``DEBT-036`` (stale) → ``DEBT-050`` for the paydown trail.
"""
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel
from sqlalchemy import BINARY, Column, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


class Attacker(SQLModel, table=True):
    """
    Per-IP **observation** row. Every distinct source IP we observe gets
    one of these. The semantic role is "observation event," not "actor
    identity" — an actor rotating across N IPs produces N rows here.

    The deduped actor view lives in ``AttackerIdentity`` (one identity
    per actor; many observations per identity); the per-operation view
    lives in ``Campaign``. ``identity_id`` is set by the clusterer
    worker once it resolves which observations are the same hands.
    NULL while the clusterer hasn't run on this row yet.

    See ``development/IDENTITY_RESOLUTION.md`` for the three-level
    hierarchy rationale.
    """
    __tablename__ = "attackers"
    uuid: str = Field(primary_key=True)
    ip: str = Field(index=True)
    identity_id: Optional[str] = Field(
        default=None,
        foreign_key="attacker_identities.uuid",
        index=True,
    )
    first_seen: datetime = Field(index=True)
    last_seen: datetime = Field(index=True)
    event_count: int = Field(default=0)
    service_count: int = Field(default=0)
    decky_count: int = Field(default=0)
    # JSON blobs — these grow over the attacker's lifetime.  Use MEDIUMTEXT on
    # MySQL (16 MiB) for the fields that accumulate (fingerprints, commands,
    # and the deckies/services lists that are unbounded in principle).
    services: str = Field(
        default="[]", sa_column=Column("services", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[str]
    deckies: str = Field(
        default="[]", sa_column=Column("deckies", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[str], first-contact ordered
    traversal_path: Optional[str] = Field(
        default=None, sa_column=Column("traversal_path", Text, nullable=True)
    )  # "decky-01 → decky-03 → decky-05"
    is_traversal: bool = Field(default=False)
    bounty_count: int = Field(default=0)
    credential_count: int = Field(default=0)
    fingerprints: str = Field(
        default="[]", sa_column=Column("fingerprints", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[dict] — bounty fingerprints
    commands: str = Field(
        default="[]", sa_column=Column("commands", _BIG_TEXT, nullable=False, default="[]")
    )  # JSON list[dict] — commands per service/decky
    # GeoIP enrichment (populated by the profiler from decnet.geoip.enrich_ip).
    # Nullable because private / loopback / IPv6 sources never resolve.
    country_code: Optional[str] = Field(default=None, max_length=2, index=True)
    country_source: Optional[str] = Field(default=None, max_length=16)
    # ASN enrichment (populated by the profiler from decnet.asn.enrich_ip).
    # Nullable for the same reasons as country_code, plus IPs not currently
    # announced in the global BGP table (e.g. CGNAT, dark space).
    asn: Optional[int] = Field(default=None, index=True)
    as_name: Optional[str] = Field(default=None, max_length=128)
    asn_source: Optional[str] = Field(default=None, max_length=16)
    # Reverse-DNS (PTR) name, one-shot resolved by the profiler at first
    # sighting. Nullable — many attackers run infra with no rDNS, and
    # private/loopback addresses never resolve.  256 chars matches
    # RFC 1035 max hostname length.
    ptr_record: Optional[str] = Field(default=None, max_length=256)
    # Substrate-rotation telemetry, maintained by
    # ``decnet.correlation.fingerprint_rotation.record_fingerprint`` whenever
    # the prober observes a new hash for an (attacker, port, probe_type)
    # triple it has seen before.  Lets the dashboard render "rotated 3×
    # last 24h" without joining to AttackerFingerprintState.
    rotation_count: int = Field(default=0)
    last_rotation_at: Optional[datetime] = Field(default=None, index=True)
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )


class AttackerFingerprintState(SQLModel, table=True):
    """Per-(attacker, port, probe_type) latest-hash row.

    Sole purpose: give the prober memory across runs so it can detect when
    an attacker's HASSH/JARM/TCP fingerprint flips for the same port — i.e.
    they rotated their VPS, rebuilt their SSH server, swapped their TLS
    cert.  Diff detection lives in
    ``decnet.correlation.fingerprint_rotation``; the prober calls into
    that library inline at each emit site and this table is the only
    persistence it needs.

    Bounded by ``attackers × probe families × ports`` — small in practice;
    a busy fleet sees O(thousands) of rows, not O(millions).
    """
    __tablename__ = "attacker_fingerprint_state"
    uuid: str = Field(primary_key=True)
    attacker_uuid: str = Field(foreign_key="attackers.uuid", index=True)
    port: int
    probe_type: str = Field(max_length=16)  # "jarm" | "hassh" | "tcpfp"
    last_hash: str = Field(max_length=128)
    last_seen: datetime = Field(index=True)
    rotation_count: int = Field(default=0)
    __table_args__ = (
        UniqueConstraint(
            "attacker_uuid", "port", "probe_type",
            name="uq_attacker_fingerprint_state_natural",
        ),
    )


class AttackerIdentity(SQLModel, table=True):
    """
    Resolved actor identity — the dedup'd "same hands" row that one or
    more ``Attacker`` observations FK into. Populated by the (future)
    clusterer worker; NULL on every observation until it runs.

    Why a separate table from ``Attacker``: an actor rotating across N
    IPs produces N observation rows but only ONE identity row. The
    identity is recovered from signals the attacker can't cheaply
    rotate — JA3, HASSH, payload hashes, C2 callbacks, and (V2)
    keystroke-rhythm SimHash. See ``development/IDENTITY_RESOLUTION.md``.

    All clusterer-populated fields are nullable; the table ships empty
    in the schema-only PR (commit 1) and stays empty until the
    clusterer lands. Empty is valid.

    ``schema_version`` is non-negotiable from day one. Federation
    gossip in V2 will share identity vectors across operators;
    bumping feature definitions without a version field silently
    poisons receivers.
    """
    __tablename__ = "attacker_identities"
    uuid: str = Field(primary_key=True)
    schema_version: int = Field(default=1)
    # Set by the campaign clusterer. The ``campaigns`` table now
    # exists; this is a real FK. Nullable until the campaign clusterer
    # has run on this identity row.
    campaign_id: Optional[str] = Field(
        default=None, foreign_key="campaigns.uuid", index=True
    )
    first_seen_at: Optional[datetime] = Field(default=None, index=True)
    last_seen_at: Optional[datetime] = Field(default=None, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    # Identity-cohesion score from the clusterer. Range [0, 1]; null
    # until the clusterer writes. Higher = more confident the
    # observations linked to this identity are the same hands.
    confidence: Optional[float] = Field(default=None)
    # Denormalized count of FK'd Attacker rows. Maintained by the
    # clusterer when it links/unlinks. Cheap dashboard read.
    observation_count: int = Field(default=0)
    # Fingerprint summary columns. JSON-serialized list[str] in TEXT
    # because: (a) federation gossip wants this exact shape on the
    # wire, (b) MySQL can't index BLOB/TEXT without prefix lengths,
    # (c) actors can present multiple JA3/HASSH values across tools
    # so a scalar column is wrong.
    ja3_hashes: Optional[str] = Field(
        default=None, sa_column=Column("ja3_hashes", Text, nullable=True)
    )
    hassh_hashes: Optional[str] = Field(
        default=None, sa_column=Column("hassh_hashes", Text, nullable=True)
    )
    ja4h_hashes: Optional[str] = Field(
        default=None, sa_column=Column("ja4h_hashes", Text, nullable=True)
    )
    ja4_quic_hashes: Optional[str] = Field(
        default=None, sa_column=Column("ja4_quic_hashes", Text, nullable=True)
    )
    http_versions_seen: Optional[str] = Field(
        default=None, sa_column=Column("http_versions_seen", Text, nullable=True)
    )
    # JSON list[str] — SHA-256 fingerprints of leaf certs presented by
    # attacker-run TLS servers, captured by the active prober alongside
    # JARM. Same federation-gossip rationale as ja3_hashes/hassh_hashes:
    # a self-signed cert reused across C2 nodes is an instant cluster-link
    # signal, and TEXT keeps MySQL indexable via prefix length.
    tls_cert_sha256: Optional[str] = Field(
        default=None, sa_column=Column("tls_cert_sha256", Text, nullable=True)
    )
    # Payload SimHash list — 64-bit ints serialized as hex strings.
    # SimHashes are Hamming-comparable, which is the entire reason
    # they're a list (not a set).
    payload_simhashes: Optional[str] = Field(
        default=None, sa_column=Column("payload_simhashes", Text, nullable=True)
    )
    c2_endpoints: Optional[str] = Field(
        default=None, sa_column=Column("c2_endpoints", Text, nullable=True)
    )
    # V2 keystroke-dynamics hook. Per-identity centroid (or majority
    # vote) across the identity's session-level digraph SimHashes.
    # The per-session SimHashes themselves now ride as BEHAVE
    # observations (``cognitive.*`` digraph primitive — see
    # ``development/BEHAVE-INTEGRATION.md`` and the BEHAVE-SHELL
    # registry); this column is the rollup the (future) attribution
    # engine will write into so the federation gossip layer
    # has one identity-level fingerprint to compare across operators.
    # BINARY(8) so MySQL can index without a prefix length.
    kd_digraph_simhash: Optional[bytes] = Field(
        default=None,
        sa_column=Column("kd_digraph_simhash", BINARY(8), nullable=True, index=True),
    )
    # Soft-merge audit trail. When the clusterer collapses two
    # identities, the loser's row stays in place with this set to the
    # winner's UUID — preserves the audit trail without orphaning FKs
    # from any cached subscribers. Resolvers (e.g.
    # GET /identities/{uuid}) follow the chain and surface the winner.
    merged_into_uuid: Optional[str] = Field(
        default=None, foreign_key="attacker_identities.uuid", index=True
    )
    # Operator-editable free-form notes — annotation surface for human
    # analysts ("known APT-XX cluster," "matches MISP event 1234").
    notes: Optional[str] = Field(
        default=None, sa_column=Column("notes", Text, nullable=True)
    )


class AttackerBehavior(SQLModel, table=True):
    """
    Timing & behavioral profile for an attacker, joined to Attacker by uuid.

    Kept in a separate table so the core Attacker row stays narrow and
    behavior data can be updated independently (e.g. as the sniffer observes
    more packets) without touching the event-count aggregates.
    """
    __tablename__ = "attacker_behavior"
    attacker_uuid: str = Field(primary_key=True, foreign_key="attackers.uuid")
    # OS / TCP stack fingerprint (rolled up from sniffer events)
    os_guess: Optional[str] = None
    hop_distance: Optional[int] = None
    tcp_fingerprint: str = Field(
        default="{}",
        sa_column=Column("tcp_fingerprint", Text, nullable=False, default="{}"),
    )  # JSON: window, wscale, mss, options_sig
    # Raw SSH KEX algorithm preference strings observed across HASSH probes
    # (one entry per hassh_fingerprint event). Keeping the raw ordered list
    # enables post-hoc KEX-order fingerprinting beyond the HASSH hash.
    kex_order_raw: Optional[str] = Field(
        default=None,
        sa_column=Column("kex_order_raw", Text, nullable=True),
    )  # JSON list[str] — kex_algorithms comma-separated strings
    # Sniffer-observed SSH client identification strings (RFC 4253 §4.2),
    # deduped in observation order. Captures the attacker's SSH client
    # software (e.g. "SSH-2.0-OpenSSH_9.2p1", "SSH-2.0-libssh2_1.10.0").
    ssh_client_banners: Optional[str] = Field(
        default=None,
        sa_column=Column("ssh_client_banners", Text, nullable=True),
    )  # JSON list[str]
    retransmit_count: int = Field(default=0)
    # Behavioral (derived by the profiler from log-event timing)
    behavior_class: Optional[str] = None          # beaconing | interactive | scanning | brute_force | slow_scan | mixed | unknown
    beacon_interval_s: Optional[float] = None
    beacon_jitter_pct: Optional[float] = None
    tool_guesses: Optional[str] = None            # JSON list[str] — all matched tools
    timing_stats: str = Field(
        default="{}",
        sa_column=Column("timing_stats", Text, nullable=False, default="{}"),
    )  # JSON: mean/median/stdev/min/max IAT
    phase_sequence: str = Field(
        default="{}",
        sa_column=Column("phase_sequence", Text, nullable=False, default="{}"),
    )  # JSON: recon_end/exfil_start/latency
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )


class SmtpTarget(SQLModel, table=True):
    """
    Per-attacker list of victim domains observed via the SMTP honeypots.

    Each row is one (attacker_uuid, domain) pair — an attacker who relays
    mail to 500 addresses at acme.com collapses into a single row with
    count=500. Only the *domain* is stored; local-parts (the bit before
    `@`) are dropped at ingestion, so this table contains no PII beyond
    the target organisation's identity.

    Shape is designed for future V2 federation gossip: the
    `smtp_target_seen(domain)` query returns aggregate counts with zero
    cross-org attacker leakage — each operator can answer "have you seen
    this domain being targeted?" without exposing *which* attackers did.
    """
    __tablename__ = "smtp_targets"
    id: Optional[int] = Field(default=None, primary_key=True)
    attacker_uuid: str = Field(foreign_key="attackers.uuid", index=True)
    domain: str = Field(index=True)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    # Aggregate counter — one rcpt_to / message_accepted recipient bumps this.
    count: int = Field(default=1)
    __table_args__ = (
        UniqueConstraint("attacker_uuid", "domain", name="uq_smtp_targets_attacker_domain"),
    )


class AttackersResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]
