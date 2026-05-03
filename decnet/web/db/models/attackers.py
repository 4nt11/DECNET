"""Attacker core + per-attacker behavioral and per-session profile rows."""
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel
from sqlalchemy import BINARY, Column, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


# ─── Keystroke-dynamics tuning constants ──────────────────────────────────────
#
# These are the semantic thresholds the session-profile ingester (DEBT-036)
# uses to bucket IATs and decide what "started a new action" means. Keeping
# them here (not inline in the ingester) so that:
#   * the schema docstrings below can reference exact boundaries instead of
#     copy-pasted magic numbers, and
#   * a future calibration pass against real honeypot session data only has
#     to touch one place.
# All values in seconds.

KD_PAUSE_BURST_MAX_S: float = 0.2   # IAT < this = muscle-memory digraph
KD_PAUSE_THINK_MAX_S: float = 1.5   # IAT < this = semantic / context-switch pause
                                    # everything ≥ this lands in the distracted bucket
KD_START_OF_ACTION_IDLE_S: float = 2.0  # idle gap that counts as "new action"
                                        # raised from 1s — 1s still catches a lot of
                                        # mid-command hesitation, 2s is closer to
                                        # empirical "meaningfully new action"


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
    # V2 keystroke-dynamics hook. Same shape as
    # SessionProfile.kd_digraph_simhash; this is the centroid (or
    # majority vote) across the identity's sessions. BINARY(8) so
    # MySQL can index without a prefix length, same as session_profile.
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


class SessionProfile(SQLModel, table=True):
    """
    Per-session keystroke-dynamics fingerprint.

    One row per recorded interactive session. Pre-v1 the ingestion job
    that populates these columns is not yet built (tracked as gap #2 in
    SIGNAL_CAPTURE_AUDIT.md); the table ships empty so that:
      * downstream correlation/federation work can target a stable schema, and
      * `schema_version` is committed to storage from day one — federation
        gossip in v2 requires cross-operator compatibility, and retrofitting
        a version column after rows exist is painful.

    All feature columns are nullable so the empty write path (one row per
    closed session) is valid without the behavioral analyzer online yet.
    """
    __tablename__ = "session_profile"
    sid: str = Field(primary_key=True)                  # session UUID
    log_id: Optional[int] = Field(
        default=None, foreign_key="logs.id", index=True
    )
    schema_version: int = Field(default=1)
    # ──────────────────────────────────────────────────────────────────────
    # Keystroke-dynamics feature columns (kd_*).
    #
    # Intended use:   session clustering and tooling attribution
    #                 ("is this the same typist?" / "is this a known C2
    #                 framework's paste cadence?").
    # Explicitly NOT for: attribution to named individuals, access or
    #                 admission decisions, any ML-driven identity lookup,
    #                 or biometric-login-style user identification. Those
    #                 framings push into legal/ethics territory we don't
    #                 want this project walking into by accident.
    # PII discipline: every kd_* column aggregates CHARACTERS and TIMING
    #                 only — never raw input-stream content. Attacker
    #                 passwords typed over SSH must not land here.
    # Nulls semantic: a null means "ingester hasn't run on this session
    #                 yet", not "zero events". Consumers should treat
    #                 null as absent, not as a computed zero.
    # ──────────────────────────────────────────────────────────────────────
    # Inter-key interval timing moments (seconds).
    kd_iki_mean: Optional[float] = None
    kd_iki_stdev: Optional[float] = None
    kd_iki_p50: Optional[float] = None
    kd_iki_p95: Optional[float] = None
    kd_enter_latency_p50: Optional[float] = None
    kd_enter_latency_p95: Optional[float] = None
    # Cadence ratios.
    kd_burst_ratio: Optional[float] = None
    kd_think_ratio: Optional[float] = None
    # Control-character rates (events per keystroke).
    kd_ctrl_backspace: Optional[float] = None
    kd_ctrl_wkill: Optional[float] = None
    kd_ctrl_ukill: Optional[float] = None
    kd_ctrl_abort: Optional[float] = None
    kd_ctrl_eof: Optional[float] = None
    kd_arrow_rate: Optional[float] = None
    kd_tab_rate: Optional[float] = None
    # 8-byte SimHash over keystroke digraphs — Hamming-comparable across sessions.
    # Fixed-width BINARY(8) rather than BLOB: MySQL can't index BLOB/TEXT
    # columns without a prefix length, and SimHashes are always exactly 8
    # bytes so a variable-length type gains nothing here.
    #
    # PII discipline: the simhash is computed over keystroke CHARACTERS
    # (digraph bigrams), never over the raw content of the input stream —
    # attacker passwords typed over SSH must never land in this column.
    kd_digraph_simhash: Optional[bytes] = Field(
        default=None,
        sa_column=Column("kd_digraph_simhash", BINARY(8), nullable=True, index=True),
    )
    # Top-N most-common digraphs with their mean IAT, as JSON.
    # Complements kd_digraph_simhash: the simhash answers "same typist?",
    # this answers "same typist IN THE SAME MENTAL STATE?" (tired vs rested
    # vs distracted shifts bigram-specific IATs measurably). Shape:
    #   [["th", 47, 0.082], ["in", 31, 0.091], ...]  (bigram, count, mean_iat_s)
    # Bounded by the ingester to N≤32 to cap row width.
    #
    # TODO(DEBT-036 upgrade path): JSON-in-TEXT is fine for v1's
    # "surface the typist's top digraphs on the attacker page" use
    # case, but every similarity query (e.g. "find sessions where the
    # 'th' digraph mean IAT is within 20 ms of this one") has to pull
    # the string, parse JSON, compare — O(sessions) with a constant
    # overhead per row. If that query shape becomes hot, promote to a
    # dedicated `session_bigram_stats(sid, bigram, count, mean_iat_s)`
    # table with a (bigram, mean_iat_s) index, or a JSONB column on
    # Postgres with a GIN index. Either is straightforward, neither
    # changes the write-side ingester materially.
    kd_top_bigrams: Optional[str] = Field(
        default=None, sa_column=Column("kd_top_bigrams", Text, nullable=True),
    )
    # IAT of the first keystroke following an idle gap >
    # KD_START_OF_ACTION_IDLE_S (or the session-start gap before the
    # very first keystroke). Separates "initiating a command" from
    # "executing a remembered one" — real humans have measurable
    # start-of-action latency, bots don't. Median across all such
    # initiations in the session, seconds.
    #
    # Prompt-agnostic on purpose: PS1 / multi-line prompts / sudo
    # password prompts make prompt-anchored detection fragile. The
    # idle-gap approach conflates post-prompt action-start with
    # mid-session think-and-resume — acceptable for a single median
    # field; if we later want to split them, feed the concurrent
    # output-stream prompt-pattern into the ingester and fall back to
    # time-only detection when it misses.
    kd_start_of_action_latency: Optional[float] = None
    # Three-bucket pause-length histogram, counts (not ratios — raw
    # counts preserve the total-keystrokes denominator in the column
    # itself). Bucket edges are the KD_PAUSE_* module constants:
    #   burst     : IAT < KD_PAUSE_BURST_MAX_S  (muscle-memory digraphs)
    #   think     : KD_PAUSE_BURST_MAX_S ≤ IAT < KD_PAUSE_THINK_MAX_S
    #               (semantic boundary, context switch)
    #   distracted: IAT ≥ KD_PAUSE_THINK_MAX_S  (went to look something
    #               up, got paged, reading another window)
    # More discriminating than the flat burst_ratio / think_ratio pair:
    # C2 operators concentrate in the burst bucket with a thin tail;
    # opportunistic humans have a fat think bucket and a long
    # distracted tail.
    kd_pause_hist_burst: Optional[int] = None
    kd_pause_hist_think: Optional[int] = None
    kd_pause_hist_distracted: Optional[int] = None
    # Longest IAT in the session, seconds. The distracted-bucket count
    # alone can't tell "one 3-second pause" from "three 60-second
    # pauses" — both contribute 1-3 to the distracted bucket but
    # represent different behaviours (brief think vs actual
    # disengagement). max_pause_gap carries that signal in one scalar.
    kd_max_pause_gap: Optional[float] = None
    # Derived totals.
    total_keystrokes: Optional[int] = None
    session_duration_s: Optional[float] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
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
