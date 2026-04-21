"""POST /topologies/blank — create an empty editable topology.

Produces a minimal ``pending`` topology seeded with exactly one DMZ LAN
and its mandatory host-gateway decky.  Intended for the MazeNET editor
landing flow: unlike ``POST /topologies`` (which runs the generator),
this endpoint takes no generator parameters and skips the planner
entirely.  The DMZ+gateway invariant is enforced server-side so the
editor never has to special-case a "no DMZ yet" state.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field as PydanticField

from decnet.telemetry import traced as _traced
from decnet.topology.allocator import SubnetAllocator, reserved_subnets
from decnet.web.db.models import TopologySummary
from decnet.web.dependencies import repo, require_admin

router = APIRouter()


class BlankTopologyRequest(BaseModel):
    """Body for POST /topologies/blank — name only."""
    name: str = PydanticField(..., min_length=1, max_length=64)


@router.post(
    "/blank",
    tags=["MazeNET Topologies"],
    response_model=TopologySummary,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "Malformed body or invalid topology name"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Name collision or subnet pool exhausted"},
    },
)
@_traced("api.topology.create_blank")
async def api_create_blank_topology(
    body: BlankTopologyRequest,
    _admin: dict = Depends(require_admin),
) -> TopologySummary:
    # 1. Topology row
    try:
        topology_id = await repo.create_topology(
            {
                "name": body.name,
                "mode": "unihost",
                "status": "pending",
                "config_snapshot": json.dumps({"blank": True}),
            }
        )
    except Exception as exc:  # noqa: BLE001 — surface duplicate-name as 409
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # 2. DMZ LAN with auto-allocated subnet
    try:
        allocator = SubnetAllocator(
            "10.0", reserved=await reserved_subnets(repo)
        )
        subnet = allocator.next_free()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    lan_id = await repo.add_lan(
        {
            "topology_id": topology_id,
            "name": "dmz",
            "subnet": subnet,
            "is_dmz": True,
            "x": 40,
            "y": 40,
        }
    )

    # 3. DMZ-gateway decky — a normal multi-homed bridge decky.
    # `forwards_l3=True` turns on net.ipv4.ip_forward + NET_ADMIN at
    # compose time (see decnet/topology/compose.py).  No host-mode,
    # no MACVLAN — the gateway reaches the outside world via Docker
    # port publishing (see composer port emission).
    decky_uuid = await repo.add_topology_decky(
        {
            "topology_id": topology_id,
            "name": "dmz-gateway",
            "services": ["ssh"],
            "decky_config": {
                "archetype": "deaddeck",
                "forwards_l3": True,
            },
            "state": "pending",
            "x": 20,
            "y": 60,
        }
    )

    # 4. Membership edge on the DMZ — is_bridge=True marks this decky
    # as the topology's bridge gateway; forwards_l3 mirrors the decky
    # config so the generator/compose paths stay consistent.
    await repo.add_topology_edge(
        {
            "topology_id": topology_id,
            "decky_uuid": decky_uuid,
            "lan_id": lan_id,
            "is_bridge": True,
            "forwards_l3": True,
        }
    )

    row = await repo.get_topology(topology_id)
    if row is None:  # pragma: no cover — create then vanish
        raise HTTPException(status_code=500, detail="topology insert vanished")
    return TopologySummary(**row)
