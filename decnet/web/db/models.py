from datetime import datetime, timezone
from typing import Literal, Optional, Any, List, Annotated
from uuid import uuid4
from sqlalchemy import Column, Index, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlmodel import SQLModel, Field
from pydantic import BaseModel, ConfigDict, Field as PydanticField, BeforeValidator
from decnet.models import IniContent, DecnetConfig

# Use on columns that accumulate over an attacker's lifetime (commands,
# fingerprints, state blobs).  TEXT on MySQL caps at 64 KiB; MEDIUMTEXT
# stretches to 16 MiB.  SQLite has no fixed-width text types so Text()
# stays unchanged there.
_BIG_TEXT = Text().with_variant(MEDIUMTEXT(), "mysql")

def _normalize_null(v: Any) -> Any:
    if isinstance(v, str) and v.lower() in ("null", "undefined", ""):
        return None
    return v

NullableDatetime = Annotated[Optional[datetime], BeforeValidator(_normalize_null)]
NullableString = Annotated[Optional[str], BeforeValidator(_normalize_null)]

# --- Database Tables (SQLModel) ---

class User(SQLModel, table=True):
    __tablename__ = "users"
    uuid: str = Field(primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    role: str = Field(default="viewer")
    must_change_password: bool = Field(default=False)

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


class State(SQLModel, table=True):
    __tablename__ = "state"
    key: str = Field(primary_key=True)
    # JSON-serialized DecnetConfig or other state blobs — can be large as
    # deckies/services accumulate.  MEDIUMTEXT on MySQL (16 MiB ceiling).
    value: str = Field(sa_column=Column("value", _BIG_TEXT, nullable=False))


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
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )


class SwarmHost(SQLModel, table=True):
    """A worker host enrolled into a DECNET swarm.

    Rows exist only on the master.  Populated by `decnet swarm enroll` and
    read by the swarm controller when sharding deckies onto workers.
    """
    __tablename__ = "swarm_hosts"
    uuid: str = Field(primary_key=True)
    name: str = Field(index=True, unique=True)
    address: str  # IP or hostname reachable by the master
    agent_port: int = Field(default=8765)
    status: str = Field(default="enrolled", index=True)
    # ISO-8601 string of the last successful agent /health probe
    last_heartbeat: Optional[datetime] = Field(default=None)
    client_cert_fingerprint: str  # SHA-256 hex of worker's issued client cert
    # SHA-256 hex of the updater-identity cert, if the host was enrolled
    # with ``--updater`` / ``issue_updater_bundle``. ``None`` for hosts
    # that only have an agent identity.
    updater_cert_fingerprint: Optional[str] = Field(default=None)
    # Directory on the master where the per-worker cert bundle lives
    cert_bundle_path: str
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = Field(default=None, sa_column=Column("notes", Text, nullable=True))
    # Per-host driver preference. True => deckies on this host run over IPvlan
    # (L2) instead of macvlan — required when the host is a VirtualBox guest
    # bridged over Wi-Fi, because Wi-Fi APs only allow one MAC per station
    # and macvlan's per-container MACs rotate the VM's DHCP lease.
    use_ipvlan: bool = Field(default=False)


class DeckyShard(SQLModel, table=True):
    """Mapping of a single decky to the worker host running it (swarm mode)."""
    __tablename__ = "decky_shards"
    decky_name: str = Field(primary_key=True)
    host_uuid: str = Field(foreign_key="swarm_hosts.uuid", index=True)
    # JSON list of service names running on this decky (snapshot of assignment).
    services: str = Field(sa_column=Column("services", _BIG_TEXT, nullable=False, default="[]"))
    # Full serialised DeckyConfig from the most recent dispatch or heartbeat.
    # Lets the dashboard render the same rich card (hostname/distro/archetype/
    # service_config/mutate_interval) that the local-fleet view uses, without
    # needing a live round-trip to the worker for every page render.
    decky_config: Optional[str] = Field(
        default=None, sa_column=Column("decky_config", _BIG_TEXT, nullable=True)
    )
    decky_ip: Optional[str] = Field(default=None)
    state: str = Field(default="pending", index=True)  # pending|running|failed|torn_down|degraded|tearing_down|teardown_failed
    last_error: Optional[str] = Field(default=None, sa_column=Column("last_error", Text, nullable=True))
    compose_hash: Optional[str] = Field(default=None)
    # Timestamp of the last heartbeat that echoed this shard; lets the UI
    # show "stale" decks whose agent has gone silent.
    last_seen: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


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

# --- MazeNET tables ---
# Nested deception topologies: an arbitrary-depth DAG of LANs connected by
# multi-homed "bridge" deckies.  Purpose-built; disjoint from DeckyShard which
# remains SWARM-only.

class Topology(SQLModel, table=True):
    __tablename__ = "topologies"
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True, unique=True)
    mode: str = Field(default="unihost")  # unihost|agent
    # When ``mode == "agent"``, pins this topology to a specific enrolled
    # worker.  ``None`` for unihost topologies (master-local deploy).
    target_host_uuid: Optional[str] = Field(
        default=None, foreign_key="swarm_hosts.uuid", index=True
    )
    # Full TopologyConfig snapshot (including seed) used at generation time.
    config_snapshot: str = Field(
        sa_column=Column("config_snapshot", _BIG_TEXT, nullable=False, default="{}")
    )
    status: str = Field(
        default="pending", index=True
    )  # pending|deploying|active|degraded|failed|tearing_down|torn_down
    status_changed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    # Optimistic-concurrency token.  Bumped by repo methods that mutate
    # the topology or any child row when an expected_version is supplied.
    # Callers pass their last-seen version; mismatch raises VersionConflict.
    version: int = Field(default=1, nullable=False)
    # Set by the heartbeat handler when an agent's reported
    # ``applied_version_hash`` diverges from what we expect it to be
    # running.  Drained by the mutator watch loop, which re-pushes via
    # AgentClient and clears the flag.  NULL for unihost topologies.
    needs_resync: bool = Field(default=False, nullable=False)


class LAN(SQLModel, table=True):
    __tablename__ = "lans"
    __table_args__ = (UniqueConstraint("topology_id", "name", name="uq_lan_topology_name"),)
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    topology_id: str = Field(foreign_key="topologies.id", index=True)
    name: str
    # Populated after the Docker network is created; nullable before deploy.
    docker_network_id: Optional[str] = Field(default=None)
    subnet: str
    is_dmz: bool = Field(default=False)
    # Canvas layout coordinates (set by the web editor).  Nullable so
    # generator-emitted LANs don't need auto-layout at generation time.
    x: Optional[float] = Field(default=None)
    y: Optional[float] = Field(default=None)


class TopologyDecky(SQLModel, table=True):
    """A decky belonging to a MazeNET topology.

    Disjoint from DeckyShard (which is SWARM-only).  UUID PK; decky name is
    unique only within a topology, so two topologies can both have a
    ``decky-01`` without colliding.
    """
    __tablename__ = "topology_deckies"
    __table_args__ = (
        UniqueConstraint("topology_id", "name", name="uq_topology_decky_name"),
    )
    uuid: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    topology_id: str = Field(foreign_key="topologies.id", index=True)
    name: str
    # JSON list[str] of service names on this decky (snapshot of assignment).
    services: str = Field(
        sa_column=Column("services", _BIG_TEXT, nullable=False, default="[]")
    )
    # Full serialised DeckyConfig snapshot — lets the dashboard render the
    # same card shape as DeckyShard without a live round-trip.
    decky_config: Optional[str] = Field(
        default=None, sa_column=Column("decky_config", _BIG_TEXT, nullable=True)
    )
    ip: Optional[str] = Field(default=None)
    # Same vocabulary as DeckyShard.state to keep dashboard rendering uniform.
    state: str = Field(
        default="pending", index=True
    )  # pending|running|failed|torn_down|degraded|tearing_down|teardown_failed
    last_error: Optional[str] = Field(
        default=None, sa_column=Column("last_error", Text, nullable=True)
    )
    compose_hash: Optional[str] = Field(default=None)
    last_seen: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # Canvas layout coordinates (set by the web editor).  Nullable so
    # generator-emitted deckies don't need auto-layout at generation time.
    x: Optional[float] = Field(default=None)
    y: Optional[float] = Field(default=None)


class TopologyEdge(SQLModel, table=True):
    """Membership edge: a decky attached to a LAN.

    A decky appearing in ≥2 edges is multi-homed (a bridge decky).
    """
    __tablename__ = "topology_edges"
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    topology_id: str = Field(foreign_key="topologies.id", index=True)
    decky_uuid: str = Field(foreign_key="topology_deckies.uuid", index=True)
    lan_id: str = Field(foreign_key="lans.id", index=True)
    is_bridge: bool = Field(default=False)
    forwards_l3: bool = Field(default=False)


class TopologyStatusEvent(SQLModel, table=True):
    """Append-only audit log of topology status transitions."""
    __tablename__ = "topology_status_events"
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    topology_id: str = Field(foreign_key="topologies.id", index=True)
    from_status: str
    to_status: str
    at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    reason: Optional[str] = Field(
        default=None, sa_column=Column("reason", Text, nullable=True)
    )


class TopologyMutation(SQLModel, table=True):
    """Operator-requested live mutation for an active MazeNET topology.

    Each row is one intent (add LAN, attach decky, etc.).  The mutator's
    reconciler claims ``pending`` rows atomically (see
    ``SQLModelRepository.claim_next_mutation``), applies them against
    Docker, and writes ``applied`` or ``failed`` back.  The ``(state,
    topology_id)`` composite index keeps the watch-loop guard query
    cheap even with years of mutation history.
    """
    __tablename__ = "topology_mutations"
    __table_args__ = (
        Index(
            "ix_topology_mutations_state_topology",
            "state",
            "topology_id",
        ),
    )
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    topology_id: str = Field(foreign_key="topologies.id", index=True)
    # add_lan|remove_lan|attach_decky|detach_decky|remove_decky|
    # update_decky|update_lan
    op: str = Field(index=True)
    # JSON-serialised op payload (keys depend on ``op``).
    payload: str = Field(
        sa_column=Column("payload", _BIG_TEXT, nullable=False, default="{}")
    )
    # pending|applying|applied|failed
    state: str = Field(default="pending", index=True)
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    applied_at: Optional[datetime] = Field(default=None)
    reason: Optional[str] = Field(
        default=None, sa_column=Column("reason", Text, nullable=True)
    )


# --- API Request/Response Models (Pydantic) ---

class Token(BaseModel):
    access_token: str
    token_type: str
    must_change_password: bool = False

class LoginRequest(BaseModel):
    username: str
    password: str = PydanticField(..., max_length=72)

class ChangePasswordRequest(BaseModel):
    old_password: str = PydanticField(..., max_length=72)
    new_password: str = PydanticField(..., max_length=72)

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

class AttackersResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[dict[str, Any]]

class StatsResponse(BaseModel):
    total_logs: int
    unique_attackers: int
    active_deckies: int
    deployed_deckies: int

class MutateIntervalRequest(BaseModel):
    # Human-readable duration: <number><unit> where unit is m(inutes), d(ays), M(onths), y/Y(ears).
    # Minimum granularity is 1 minute. Seconds are not accepted.
    mutate_interval: Optional[str] = PydanticField(None, pattern=r"^[1-9]\d*[mdMyY]$")

class DeployIniRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # This field now enforces strict INI structure during Pydantic initialization.
    # The OpenAPI schema correctly shows it as a required string.
    ini_content: IniContent = PydanticField(..., description="A valid INI formatted string")


# --- Configuration Models ---

class CreateUserRequest(BaseModel):
    username: str = PydanticField(..., min_length=1, max_length=64)
    password: str = PydanticField(..., min_length=8, max_length=72)
    role: Literal["admin", "viewer"] = "viewer"

class UpdateUserRoleRequest(BaseModel):
    role: Literal["admin", "viewer"]

class ResetUserPasswordRequest(BaseModel):
    new_password: str = PydanticField(..., min_length=8, max_length=72)

class DeploymentLimitRequest(BaseModel):
    deployment_limit: int = PydanticField(..., ge=1, le=500)

class GlobalMutationIntervalRequest(BaseModel):
    global_mutation_interval: str = PydanticField(..., pattern=r"^[1-9]\d*[mdMyY]$")

class UserResponse(BaseModel):
    uuid: str
    username: str
    role: str
    must_change_password: bool

class ConfigResponse(BaseModel):
    role: str
    deployment_limit: int
    global_mutation_interval: str

class AdminConfigResponse(ConfigResponse):
    users: List[UserResponse]


class ComponentHealth(BaseModel):
    status: Literal["ok", "failing"]
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    components: dict[str, ComponentHealth]


# --- Swarm API DTOs ---
# Request/response contracts for the master-side swarm controller
# (decnet/web/swarm_api.py).  The underlying SQLModel tables — SwarmHost and
# DeckyShard — live above; these are the HTTP-facing shapes.

class SwarmEnrollRequest(BaseModel):
    # x509 CommonName is capped at 64 bytes (RFC 5280 UB-common-name) — the
    # cert issuer would reject anything longer with a ValueError.
    # Pattern: ASCII hostname-safe characters only. The name is embedded
    # both in the CN and as a SAN DNS entry; x509.DNSName only accepts
    # A-label ASCII, so non-ASCII would blow up at issuance.
    name: str = PydanticField(
        ..., min_length=1, max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._\-]*$",
    )
    address: str = PydanticField(
        ..., min_length=1, max_length=253,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:\-]*$",
        description="IP or DNS the master uses to reach the worker",
    )
    agent_port: int = PydanticField(default=8765, ge=1, le=65535)
    sans: list[
        Annotated[
            str,
            PydanticField(
                min_length=1, max_length=253,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9._:\-]*$",
            ),
        ]
    ] = PydanticField(
        default_factory=list,
        description="Extra SANs (IPs / hostnames) to embed in the worker cert",
    )
    notes: Optional[str] = None
    issue_updater_bundle: bool = PydanticField(
        default=False,
        description="If true, also issue an updater cert (CN=updater@<name>) for the remote self-updater",
    )


class SwarmUpdaterBundle(BaseModel):
    """Subset of SwarmEnrolledBundle for the updater identity."""
    fingerprint: str
    updater_cert_pem: str
    updater_key_pem: str


class SwarmEnrolledBundle(BaseModel):
    """Cert bundle returned to the operator — must be delivered to the worker."""
    host_uuid: str
    name: str
    address: str
    agent_port: int
    fingerprint: str
    ca_cert_pem: str
    worker_cert_pem: str
    worker_key_pem: str
    updater: Optional[SwarmUpdaterBundle] = None


class SwarmHostView(BaseModel):
    uuid: str
    name: str
    address: str
    agent_port: int
    status: str
    last_heartbeat: Optional[datetime] = None
    client_cert_fingerprint: str
    updater_cert_fingerprint: Optional[str] = None
    enrolled_at: datetime
    notes: Optional[str] = None
    use_ipvlan: bool = False


class DeckyShardView(BaseModel):
    """One decky → host mapping, enriched with the host's identity for display."""
    decky_name: str
    decky_ip: Optional[str] = None  # resolved from the stored DecnetConfig at read time
    host_uuid: str
    host_name: str
    host_address: str
    host_status: str
    services: list[str]
    state: str
    last_error: Optional[str] = None
    compose_hash: Optional[str] = None
    updated_at: datetime
    # Enriched fields lifted from the stored DeckyConfig snapshot so the
    # dashboard can render the same card shape as the local-fleet view.
    hostname: Optional[str] = None
    distro: Optional[str] = None
    archetype: Optional[str] = None
    service_config: dict[str, dict[str, Any]] = {}
    mutate_interval: Optional[int] = None
    last_mutated: float = 0.0
    last_seen: Optional[datetime] = None


class SwarmDeployRequest(BaseModel):
    config: DecnetConfig
    dry_run: bool = False
    no_cache: bool = False


class SwarmTeardownRequest(BaseModel):
    host_uuid: Optional[str] = PydanticField(
        default=None,
        description="If set, tear down only this worker; otherwise tear down all hosts",
    )
    decky_id: Optional[str] = None


class SwarmHostResult(BaseModel):
    host_uuid: str
    host_name: str
    ok: bool
    detail: Any | None = None


class SwarmDeployResponse(BaseModel):
    results: list[SwarmHostResult]


class SwarmHostHealth(BaseModel):
    host_uuid: str
    name: str
    address: str
    reachable: bool
    detail: Any | None = None


class SwarmCheckResponse(BaseModel):
    results: list[SwarmHostHealth]


# --- Remote Updates (master → worker /updater) DTOs ---
# Powers the dashboard's Remote Updates page. The master dashboard calls
# these (auth-gated) endpoints; internally they fan out to each worker's
# updater daemon over mTLS via UpdaterClient.

class HostReleaseInfo(BaseModel):
    host_uuid: str
    host_name: str
    address: str
    reachable: bool
    # These fields mirror the updater's /health payload when reachable; they
    # are all Optional so an unreachable host still serializes cleanly.
    agent_status: Optional[str] = None
    current_sha: Optional[str] = None
    previous_sha: Optional[str] = None
    releases: list[dict[str, Any]] = PydanticField(default_factory=list)
    detail: Optional[str] = None  # populated when unreachable


class HostReleasesResponse(BaseModel):
    hosts: list[HostReleaseInfo]


class PushUpdateRequest(BaseModel):
    host_uuids: Optional[list[str]] = PydanticField(
        default=None,
        description="Target specific hosts; mutually exclusive with 'all'.",
    )
    all: bool = PydanticField(default=False, description="Target every non-decommissioned host with an updater bundle.")
    include_self: bool = PydanticField(
        default=False,
        description="After a successful /update, also push /update-self to upgrade the updater itself.",
    )
    exclude: list[str] = PydanticField(
        default_factory=list,
        description="Additional tarball exclude globs (on top of the built-in defaults).",
    )


class PushUpdateResult(BaseModel):
    host_uuid: str
    host_name: str
    # updated = /update 200. rolled-back = /update 409 (auto-recovered).
    # failed = transport error or non-200/409 response. self-updated = /update-self succeeded.
    status: Literal["updated", "rolled-back", "failed", "self-updated", "self-failed"]
    http_status: Optional[int] = None
    sha: Optional[str] = None
    detail: Optional[str] = None
    stderr: Optional[str] = None


class PushUpdateResponse(BaseModel):
    sha: str
    tarball_bytes: int
    results: list[PushUpdateResult]


class RollbackRequest(BaseModel):
    host_uuid: str = PydanticField(..., description="Host to roll back to its previous release slot.")


class RollbackResponse(BaseModel):
    host_uuid: str
    host_name: str
    status: Literal["rolled-back", "failed"]
    http_status: Optional[int] = None
    detail: Optional[str] = None


# --- MazeNET Topology REST DTOs (phase 3) ---
# Request/response shapes for /api/v1/topologies. All write paths are
# admin-only; reads accept admin or viewer. Child CRUD is pending-only;
# mutations of active|degraded topologies go through the queue.


class TopologyGenerateRequest(BaseModel):
    """Body for POST /topologies — mirrors the `topology generate` CLI."""
    name: str = PydanticField(..., min_length=1, max_length=64)
    mode: str = PydanticField(default="unihost", pattern=r"^(unihost|agent)$")
    target_host_uuid: Optional[str] = None
    depth: int = PydanticField(..., ge=1, le=16)
    branching_factor: int = PydanticField(..., ge=1, le=8)
    deckies_per_lan_min: int = PydanticField(default=1, ge=0, le=32)
    deckies_per_lan_max: int = PydanticField(default=3, ge=1, le=32)
    bridge_forward_probability: float = PydanticField(default=1.0, ge=0.0, le=1.0)
    cross_edge_probability: float = PydanticField(default=0.0, ge=0.0, le=1.0)
    services_explicit: Optional[list[str]] = None
    randomize_services: bool = True
    seed: Optional[int] = PydanticField(default=None, ge=0)


class TopologySummary(BaseModel):
    """List-row shape for GET /topologies."""
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    mode: str
    target_host_uuid: Optional[str] = None
    status: str
    version: int
    needs_resync: bool = False
    created_at: datetime
    status_changed_at: Optional[datetime] = None


class TopologyListResponse(BaseModel):
    total: int
    limit: Optional[int] = None
    offset: Optional[int] = None
    data: list[TopologySummary]


class LANRow(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    topology_id: str
    name: str
    subnet: str
    is_dmz: bool = False
    docker_network_id: Optional[str] = None
    x: Optional[float] = None
    y: Optional[float] = None


class DeckyRow(BaseModel):
    model_config = ConfigDict(extra="ignore")
    uuid: str
    topology_id: str
    name: str
    services: list[str] = PydanticField(default_factory=list)
    decky_config: Optional[dict[str, Any]] = None
    ip: Optional[str] = None
    state: str
    last_error: Optional[str] = None
    x: Optional[float] = None
    y: Optional[float] = None


class EdgeRow(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    topology_id: str
    decky_uuid: str
    lan_id: str
    is_bridge: bool = False
    forwards_l3: bool = False


class TopologyDetail(BaseModel):
    """Hydrated topology — mirrors persistence.hydrate() output.

    ``topology`` uses :class:`TopologySummary` which already exposes
    ``target_host_uuid`` — agent-targeted topologies surface their
    pinned host through that field.
    """
    topology: TopologySummary
    lans: list[LANRow]
    deckies: list[DeckyRow]
    edges: list[EdgeRow]


class TopologyStatusEventRow(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    topology_id: str
    from_status: str
    to_status: str
    at: datetime
    reason: Optional[str] = None


class LANCreateRequest(BaseModel):
    name: str = PydanticField(..., min_length=1, max_length=64)
    subnet: Optional[str] = None
    is_dmz: bool = False
    x: Optional[float] = None
    y: Optional[float] = None
    expected_version: Optional[int] = None


class LANUpdateRequest(BaseModel):
    name: Optional[str] = None
    subnet: Optional[str] = None
    is_dmz: Optional[bool] = None
    x: Optional[float] = None
    y: Optional[float] = None
    expected_version: Optional[int] = None


class DeckyCreateRequest(BaseModel):
    name: str = PydanticField(..., min_length=1, max_length=64)
    services: list[str] = PydanticField(default_factory=list)
    decky_config: Optional[dict[str, Any]] = None
    x: Optional[float] = None
    y: Optional[float] = None
    expected_version: Optional[int] = None


class DeckyUpdateRequest(BaseModel):
    name: Optional[str] = None
    services: Optional[list[str]] = None
    decky_config: Optional[dict[str, Any]] = None
    x: Optional[float] = None
    y: Optional[float] = None
    expected_version: Optional[int] = None


class EdgeCreateRequest(BaseModel):
    decky_uuid: str
    lan_id: str
    is_bridge: bool = False
    forwards_l3: bool = False
    expected_version: Optional[int] = None


_MUTATION_OPS = Literal[
    "add_lan",
    "remove_lan",
    "attach_decky",
    "detach_decky",
    "remove_decky",
    "update_decky",
    "update_lan",
]


class MutationEnqueueRequest(BaseModel):
    op: _MUTATION_OPS
    payload: dict[str, Any] = PydanticField(default_factory=dict)
    expected_version: Optional[int] = None


def _decode_json_payload(v: Any) -> Any:
    """Accept either a dict or a JSON-encoded string for mutation payloads."""
    if isinstance(v, str):
        import json as _json
        return _json.loads(v) if v else {}
    return v


_MutationPayload = Annotated[dict[str, Any], BeforeValidator(_decode_json_payload)]


class MutationRow(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    topology_id: str
    op: str
    payload: _MutationPayload = PydanticField(default_factory=dict)
    state: str
    requested_at: datetime
    applied_at: Optional[datetime] = None
    reason: Optional[str] = None


class MutationEnqueueResponse(BaseModel):
    mutation_id: str
    state: str = "pending"


class ValidationIssueResponse(BaseModel):
    severity: str
    code: str
    message: str
    target: dict[str, Any] = PydanticField(default_factory=dict)


class ValidationErrorResponse(BaseModel):
    detail: str = "Topology validation failed"
    issues: list[ValidationIssueResponse]


class VersionConflictResponse(BaseModel):
    detail: str = "Topology version conflict"
    current: int
    expected: int


class NotEditableResponse(BaseModel):
    detail: str = "Topology not editable"
    status: str
    reason: Optional[str] = None


class ServiceCatalogResponse(BaseModel):
    services: list[str]


class ArchetypeEntry(BaseModel):
    slug: str
    display_name: str
    description: str
    services: list[str]
    preferred_distros: list[str]
    nmap_os: str


class ArchetypeCatalogResponse(BaseModel):
    archetypes: list[ArchetypeEntry]


class NextIPResponse(BaseModel):
    subnet: str
    ip: str


class NextSubnetResponse(BaseModel):
    subnet: str


class DeployAcceptedResponse(BaseModel):
    topology_id: str
    status: str
    dry_run: bool = False
