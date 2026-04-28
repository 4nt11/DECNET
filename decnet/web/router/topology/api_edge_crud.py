"""Edge CRUD endpoints — pending-only child mutations.

    POST   /topologies/{id}/edges
    DELETE /topologies/{id}/edges/{edge_id}

Edges are the decky↔LAN membership table (bipartite).  Creating an
edge attaches a decky to an additional LAN; deleting one detaches.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from decnet.telemetry import traced as _traced
from decnet.topology.status import (
    TopologyNotEditable,
    VersionConflict,
)
from decnet.web.db.models import EdgeCreateRequest, EdgeRow
from decnet.web.dependencies import repo, require_admin

from ._guards import assert_pending_or_409, map_repo_exception

router = APIRouter()


@router.post(
    "/{topology_id}/edges",
    tags=["MazeNET Topologies"],
    response_model=EdgeRow,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "Malformed body or unknown decky/LAN"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.edge.create")
async def api_create_edge(
    topology_id: str,
    body: EdgeCreateRequest,
    _admin: dict = Depends(require_admin),
) -> EdgeRow:
    await assert_pending_or_409(topology_id)

    # Referential integrity: decky + LAN must belong to this topology.
    deckies = await repo.list_topology_deckies(topology_id)
    if not any(d["uuid"] == body.decky_uuid for d in deckies):
        raise HTTPException(
            status_code=400,
            detail=f"decky {body.decky_uuid!r} not in topology {topology_id!r}",
        )
    lans = await repo.list_lans_for_topology(topology_id)
    if not any(r["id"] == body.lan_id for r in lans):
        raise HTTPException(
            status_code=400,
            detail=f"lan {body.lan_id!r} not in topology {topology_id!r}",
        )

    payload = {
        "topology_id": topology_id,
        "decky_uuid": body.decky_uuid,
        "lan_id": body.lan_id,
        "is_bridge": body.is_bridge,
        "forwards_l3": body.forwards_l3,
    }
    try:
        edge_id = await repo.add_topology_edge(
            payload, expected_version=body.expected_version
        )
    except (TopologyNotEditable, VersionConflict, ValueError) as exc:
        raise map_repo_exception(exc) from exc

    edges = await repo.list_topology_edges(topology_id)
    row = next((e for e in edges if e["id"] == edge_id), None)
    if row is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="Edge insert vanished")
    return EdgeRow(**row)


@router.delete(
    "/{topology_id}/edges/{edge_id}",
    tags=["MazeNET Topologies"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"description": "Malformed path"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or edge not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.edge.delete")
async def api_delete_edge(
    topology_id: str,
    edge_id: str,
    _admin: dict = Depends(require_admin),
) -> Response:
    await assert_pending_or_409(topology_id)

    edges = await repo.list_topology_edges(topology_id)
    if not any(e["id"] == edge_id for e in edges):
        raise HTTPException(status_code=404, detail="Edge not found")

    try:
        await repo.delete_topology_edge(edge_id)
    except (TopologyNotEditable, VersionConflict, ValueError) as exc:
        raise map_repo_exception(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
