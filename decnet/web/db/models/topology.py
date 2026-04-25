"""MazeNET topology tables + the REST DTOs that wrap them."""
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field as PydanticField
from sqlalchemy import Column, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


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
    # Per-LAN swarm host pin. ``None`` means "fall back to
    # ``Topology.target_host_uuid``; if that is also None, deploy on the
    # master." A LAN is one Docker bridge — bridges don't span hosts —
    # so a non-null value forces every decky in this LAN onto that host.
    host_uuid: Optional[str] = Field(
        default=None, foreign_key="swarm_hosts.uuid", index=True
    )
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
    # add_lan|remove_lan|add_decky|attach_decky|detach_decky|
    # remove_decky|update_decky|update_lan
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
    host_uuid: Optional[str] = None
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
    host_uuid: Optional[str] = None
    x: Optional[float] = None
    y: Optional[float] = None
    expected_version: Optional[int] = None


class LANUpdateRequest(BaseModel):
    name: Optional[str] = None
    subnet: Optional[str] = None
    is_dmz: Optional[bool] = None
    host_uuid: Optional[str] = None
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
    "add_decky",
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


class ReapReportResponse(BaseModel):
    live_prefixes: list[str]
    orphan_prefixes: list[str]
    containers_removed: list[str]
    networks_removed: list[str]
    errors: list[str]
