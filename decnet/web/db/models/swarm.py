# SPDX-License-Identifier: AGPL-3.0-or-later
"""Swarm host + decky shard tables and their HTTP DTOs."""
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from pydantic import BaseModel, Field as PydanticField
from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

from decnet.models import DecnetConfig

from ._base import _BIG_TEXT


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


class EnrollBundleRequest(BaseModel):
    master_host: str = PydanticField(..., min_length=1, max_length=253,
                                     description="IP/host the agent will reach back to")
    agent_name: str = PydanticField(..., pattern=r"^[a-z0-9][a-z0-9-]{0,62}$",
                                    description="Worker name (DNS-label safe)")
    with_updater: bool = PydanticField(
        default=True,
        description="Include updater cert bundle and auto-start decnet updater on the agent",
    )
    use_ipvlan: bool = PydanticField(
        default=False,
        description=(
            "Run deckies on this agent over IPvlan L2 instead of MACVLAN. "
            "Required when the agent is a VirtualBox/VMware guest bridged over Wi-Fi — "
            "Wi-Fi APs bind one MAC per station, so MACVLAN's extra container MACs "
            "rotate the VM's DHCP lease. Safe no-op on wired/bare-metal hosts."
        ),
    )
    services_ini: Optional[str] = PydanticField(
        default=None,
        description="Optional INI text shipped to the agent as /etc/decnet/services.ini",
    )


class EnrollBundleResponse(BaseModel):
    token: str
    command: str
    expires_at: datetime
    host_uuid: str
