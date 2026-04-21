"""LAN CRUD endpoints — pending-only child mutations.

    POST   /topologies/{id}/lans
    PATCH  /topologies/{id}/lans/{lan_id}
    DELETE /topologies/{id}/lans/{lan_id}
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.topology.allocator import reserved_subnets
from decnet.topology.status import (
    TopologyNotEditable,
    VersionConflict,
)
from decnet.web.db.models import LANCreateRequest, LANRow, LANUpdateRequest
from decnet.web.dependencies import repo, require_admin

from ._guards import assert_pending_or_409, map_repo_exception

log = get_logger("api.topology.lan")
router = APIRouter()


@router.post(
    "/{topology_id}/lans",
    tags=["MazeNET Topologies"],
    response_model=LANRow,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "Malformed body or invalid LAN fields"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.lan.create")
async def api_create_lan(
    topology_id: str,
    body: LANCreateRequest,
    _admin: dict = Depends(require_admin),
) -> LANRow:
    await assert_pending_or_409(topology_id)

    subnet = body.subnet
    if subnet is None:
        # Mint a free /24.  The allocator scans the claimed set and hands
        # back the next free subnet base — same logic as the catalog
        # /next-subnet endpoint, but inlined so create is atomic.
        from decnet.topology.allocator import SubnetAllocator

        allocator = SubnetAllocator(
            "10.0", reserved=await reserved_subnets(repo)
        )
        subnet = allocator.next_free()

    payload = {
        "topology_id": topology_id,
        "name": body.name,
        "subnet": subnet,
        "is_dmz": body.is_dmz,
        "x": body.x,
        "y": body.y,
    }
    try:
        lan_id = await repo.add_lan(
            payload, expected_version=body.expected_version
        )
    except (TopologyNotEditable, VersionConflict, ValueError) as exc:
        raise map_repo_exception(exc) from exc

    rows = await repo.list_lans_for_topology(topology_id)
    row = next((r for r in rows if r["id"] == lan_id), None)
    if row is None:  # pragma: no cover — would mean insert vanished
        raise HTTPException(status_code=500, detail="LAN insert vanished")

    # Auto-bridge: if this is a non-DMZ LAN, attach the topology's
    # DMZ gateway (the decky with forwards_l3=True that lives on the
    # DMZ LAN) to it.  Satisfies the DMZ_ORPHAN invariant by
    # construction — every internal LAN always has a bridge path.
    if not body.is_dmz:
        try:
            await _auto_attach_gateway(topology_id, lan_id)
        except Exception as exc:
            # Best-effort: if the gateway is missing or the edge can't
            # be written, the deploy-time validator will surface it.
            log.warning(
                "auto-bridge skipped for LAN %s in topology %s: %s",
                lan_id, topology_id, exc,
            )

    return LANRow(**row)


async def _auto_attach_gateway(topology_id: str, new_lan_id: str) -> None:
    """Attach the topology's DMZ gateway to a newly created non-DMZ LAN."""
    lans = await repo.list_lans_for_topology(topology_id)
    dmz = next((lan for lan in lans if lan.get("is_dmz")), None)
    if dmz is None:
        return

    edges = await repo.list_topology_edges(topology_id)
    gateway_uuid: str | None = None
    for e in edges:
        if e["lan_id"] != dmz["id"]:
            continue
        if e.get("forwards_l3"):
            gateway_uuid = e["decky_uuid"]
            break
    if gateway_uuid is None:
        return

    if any(
        e["decky_uuid"] == gateway_uuid and e["lan_id"] == new_lan_id
        for e in edges
    ):
        return

    await repo.add_topology_edge(
        {
            "topology_id": topology_id,
            "decky_uuid": gateway_uuid,
            "lan_id": new_lan_id,
            "is_bridge": True,
            "forwards_l3": True,
        }
    )


@router.patch(
    "/{topology_id}/lans/{lan_id}",
    tags=["MazeNET Topologies"],
    response_model=LANRow,
    responses={
        400: {"description": "Malformed body or invalid LAN fields"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or LAN not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.lan.update")
async def api_update_lan(
    topology_id: str,
    lan_id: str,
    body: LANUpdateRequest,
    _admin: dict = Depends(require_admin),
) -> LANRow:
    await assert_pending_or_409(topology_id)

    fields = body.model_dump(exclude_unset=True, exclude={"expected_version"})
    try:
        await repo.update_lan(
            lan_id,
            fields,
            expected_version=body.expected_version,
            enforce_pending=True,
        )
    except (TopologyNotEditable, VersionConflict) as exc:
        raise map_repo_exception(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    rows = await repo.list_lans_for_topology(topology_id)
    row = next((r for r in rows if r["id"] == lan_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="LAN not found")
    return LANRow(**row)


@router.delete(
    "/{topology_id}/lans/{lan_id}",
    tags=["MazeNET Topologies"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"description": "Cannot delete: LAN has orphan-risking deckies"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or LAN not found"},
        409: {"description": "Topology not editable or version conflict"},
    },
)
@_traced("api.topology.lan.delete")
async def api_delete_lan(
    topology_id: str,
    lan_id: str,
    _admin: dict = Depends(require_admin),
) -> Response:
    await assert_pending_or_409(topology_id)

    rows = await repo.list_lans_for_topology(topology_id)
    if not any(r["id"] == lan_id for r in rows):
        raise HTTPException(status_code=404, detail="LAN not found")

    try:
        await repo.delete_lan(lan_id)
    except (TopologyNotEditable, VersionConflict, ValueError) as exc:
        raise map_repo_exception(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
