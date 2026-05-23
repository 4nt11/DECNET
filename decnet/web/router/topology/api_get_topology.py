# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /topologies/{id} and /topologies/{id}/status-events."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.topology.persistence import hydrate
from decnet.web.db.models import (
    DeckyRow,
    EdgeRow,
    LANRow,
    TopologyDetail,
    TopologyStatusEventRow,
    TopologySummary,
)
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/{topology_id}",
    tags=["MazeNET Topologies"],
    response_model=TopologyDetail,
    responses={
        400: {"description": "Malformed path parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
    },
)
@_traced("api.topology.get")
async def api_get_topology(
    topology_id: str,
    _viewer: dict = Depends(require_viewer),
) -> TopologyDetail:
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    return TopologyDetail(
        topology=TopologySummary(**hydrated["topology"]),
        lans=[LANRow(**r) for r in hydrated["lans"]],
        deckies=[DeckyRow(**r) for r in hydrated["deckies"]],
        edges=[EdgeRow(**r) for r in hydrated["edges"]],
    )


@router.get(
    "/{topology_id}/status-events",
    tags=["MazeNET Topologies"],
    response_model=list[TopologyStatusEventRow],
    responses={
        400: {"description": "Malformed query parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
    },
)
@_traced("api.topology.status_events")
async def api_get_status_events(
    topology_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    _viewer: dict = Depends(require_viewer),
) -> list[TopologyStatusEventRow]:
    if await repo.get_topology(topology_id) is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    rows = await repo.list_topology_status_events(topology_id, limit=limit)
    return [TopologyStatusEventRow(**r) for r in rows]
