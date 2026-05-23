# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fleet decky table — DB mirror of ``decnet-state.json``.

The legacy unihost / MACVLAN / IPVLAN deploy path persists fleet state to a
JSON file (``/var/lib/decnet/decnet-state.json``) via
:func:`decnet.config.save_state`.  That file is consumed directly by
``decnet status``/``decnet teardown``, the sniffer, and the collector — all
host-local CLI / worker code that may run on a box without the API daemon.

The FleetDecky table is a *mirror* of that JSON state inside MySQL/SQLite so
DB-only consumers (the orchestrator, the web dashboard, the REST API) can
see fleet decoys without touching the filesystem.

Both writers — CLI ``decnet deploy`` (``engine.deployer.deploy``) and the
web/API deploy path (``web.router.fleet.api_deploy_deckies``) — write to
*both* surfaces.  A reconciler (``decnet.fleet.reconciler``) handles drift.

Schema mirrors :class:`decnet.web.db.models.swarm.DeckyShard` field-for-field
so the dashboard can render fleet rows with the same card shape.  The PK is
composite ``(host_uuid, name)`` to future-proof for multi-host motherships
(a master that runs its own local fleet AND swarm-shards onto workers).  In
unihost mode ``host_uuid`` defaults to the sentinel
:data:`LOCAL_HOST_SENTINEL`; we deliberately do NOT FK to ``swarm_hosts``
because the local mothership is not enrolled as a swarm worker.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

from ._base import _BIG_TEXT


LOCAL_HOST_SENTINEL = "local"


class FleetDecky(SQLModel, table=True):
    """A unihost / MACVLAN / IPVLAN decky deployed on the local mothership.

    Disjoint from :class:`DeckyShard` (SWARM-only) and :class:`TopologyDecky`
    (MazeNET-only).  Composite PK lets multiple hosts coexist when a future
    mothership runs both a local fleet and acts as a swarm master.
    """
    __tablename__ = "fleet_deckies"

    host_uuid: str = Field(
        default=LOCAL_HOST_SENTINEL, primary_key=True, index=True,
    )
    name: str = Field(primary_key=True)
    # JSON list of service names on this decky (snapshot of assignment).
    services: str = Field(
        sa_column=Column("services", _BIG_TEXT, nullable=False, default="[]")
    )
    # Full serialised DeckyConfig — lets the dashboard render the same rich
    # card (hostname/distro/archetype/service_config/mutate_interval) without
    # round-tripping to load_state() on every page render.
    decky_config: Optional[str] = Field(
        default=None, sa_column=Column("decky_config", _BIG_TEXT, nullable=True)
    )
    decky_ip: Optional[str] = Field(default=None)
    # pending|running|failed|torn_down|degraded|tearing_down|teardown_failed
    state: str = Field(default="pending", index=True)
    last_error: Optional[str] = Field(
        default=None, sa_column=Column("last_error", Text, nullable=True),
    )
    compose_hash: Optional[str] = Field(default=None)
    # Last reconciler observation (docker inspect) — lets the dashboard show
    # "stale" rows whose reconciler hasn't ticked.
    last_seen: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
