"""Attacker core + per-attacker behavioral and per-session profile rows."""
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel
from sqlalchemy import BINARY, Column, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


class Attacker(SQLModel, table=True):
    __tablename__ = "attackers"
    uuid: str = Field(primary_key=True)
    ip: str = Field(index=True)
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
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
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
    # Same PII discipline as kd_digraph_simhash: bigram CHARACTERS only,
    # no content. Bounded by the ingester to N≤32 to cap row width.
    kd_top_bigrams: Optional[str] = Field(
        default=None, sa_column=Column("kd_top_bigrams", Text, nullable=True),
    )
    # IAT of the first keystroke following an idle gap > 1s (or the
    # session-start gap before the first keystroke ever). Separates
    # "initiating a command" from "executing a remembered one" — real
    # humans have measurable start-of-action latency, bots don't. Median
    # across all such initiations in the session, seconds.
    kd_start_of_action_latency: Optional[float] = None
    # Three-bucket pause-length histogram, counts (not ratios — raw counts
    # preserve the total-keystrokes denominator in the column itself):
    #   burst     : IAT < 0.2s   (muscle-memory digraphs)
    #   think     : 0.2s ≤ IAT < 1.5s  (semantic boundary, context switch)
    #   distracted: IAT ≥ 1.5s   (went to look something up, got paged,
    #                             actively reading another window)
    # More discriminating than the flat burst_ratio/think_ratio pair:
    # C2 operators concentrate in the burst bucket with a thin tail;
    # opportunistic humans have a fat think bucket plus a long distracted
    # tail. Nulls indicate "ingester hasn't run yet", not "zero events".
    kd_pause_hist_burst: Optional[int] = None
    kd_pause_hist_think: Optional[int] = None
    kd_pause_hist_distracted: Optional[int] = None
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
