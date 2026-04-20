"""Decky CRUD endpoints — pending-only child mutations.

    POST   /topologies/{id}/deckies
    PATCH  /topologies/{id}/deckies/{uuid}
    DELETE /topologies/{id}/deckies/{uuid}
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from decnet.telemetry import traced as _traced
from decnet.topology.status import (
    TopologyNotEditable,
    VersionConflict,
)
from decnet.web.db.models import DeckyCreateRequest, DeckyRow, DeckyUpdateRequest
from decnet.web.dependencies import repo, require_admin

from ._guards import assert_pending_or_409, map_repo_exception

router = APIRouter()


@router.post(
    "/{topology_id}/deckies",
    tags=["MazeNET Topologies"],
    response_model=DeckyRow,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "Malformed body or invalid decky fields"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.decky.create")
async def api_create_decky(
    topology_id: str,
    body: DeckyCreateRequest,
    _admin: dict = Depends(require_admin),
) -> DeckyRow:
    await assert_pending_or_409(topology_id)

    payload = {
        "topology_id": topology_id,
        "name": body.name,
        "services": body.services,
        "decky_config": body.decky_config,
        "x": body.x,
        "y": body.y,
    }
    try:
        decky_uuid = await repo.add_topology_decky(
            payload, expected_version=body.expected_version
        )
    except (TopologyNotEditable, VersionConflict, ValueError) as exc:
        raise map_repo_exception(exc) from exc

    rows = await repo.list_topology_deckies(topology_id)
    row = next((r for r in rows if r["uuid"] == decky_uuid), None)
    if row is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="Decky insert vanished")
    return DeckyRow(**row)


@router.patch(
    "/{topology_id}/deckies/{decky_uuid}",
    tags=["MazeNET Topologies"],
    response_model=DeckyRow,
    responses={
        400: {"description": "Malformed body"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or decky not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.decky.update")
async def api_update_decky(
    topology_id: str,
    decky_uuid: str,
    body: DeckyUpdateRequest,
    _admin: dict = Depends(require_admin),
) -> DeckyRow:
    await assert_pending_or_409(topology_id)

    fields = body.model_dump(exclude_unset=True, exclude={"expected_version"})
    try:
        await repo.update_topology_decky(
            decky_uuid,
            fields,
            expected_version=body.expected_version,
            enforce_pending=True,
        )
    except (TopologyNotEditable, VersionConflict) as exc:
        raise map_repo_exception(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    rows = await repo.list_topology_deckies(topology_id)
    row = next((r for r in rows if r["uuid"] == decky_uuid), None)
    if row is None:
        raise HTTPException(status_code=404, detail="Decky not found")
    return DeckyRow(**row)


@router.delete(
    "/{topology_id}/deckies/{decky_uuid}",
    tags=["MazeNET Topologies"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"description": "Malformed path"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or decky not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.decky.delete")
async def api_delete_decky(
    topology_id: str,
    decky_uuid: str,
    _admin: dict = Depends(require_admin),
) -> Response:
    await assert_pending_or_409(topology_id)

    rows = await repo.list_topology_deckies(topology_id)
    if not any(r["uuid"] == decky_uuid for r in rows):
        raise HTTPException(status_code=404, detail="Decky not found")

    try:
        await repo.delete_topology_decky(decky_uuid)
    except (TopologyNotEditable, VersionConflict, ValueError) as exc:
        raise map_repo_exception(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
