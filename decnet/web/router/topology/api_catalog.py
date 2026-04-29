"""Read-only catalog endpoints — services, next-subnet, next-ip.

These wrap fleet/allocator helpers so the phase-4 canvas UI can lean
on the server for allocation instead of shipping the logic client-side.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.archetypes import all_archetypes
from decnet.fleet import all_service_names
from decnet.telemetry import traced as _traced
from decnet.topology.allocator import (
    AllocatorExhausted,
    IPAllocator,
    SubnetAllocator,
    reserved_subnets,
)
from decnet.web.db.models import (
    ArchetypeCatalogResponse,
    ArchetypeEntry,
    NextIPResponse,
    NextSubnetResponse,
    ServiceCatalogResponse,
)
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/services",
    tags=["MazeNET Topologies"],
    response_model=ServiceCatalogResponse,
    responses={
        400: {"description": "Malformed query parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.topology.catalog.services")
async def api_list_services(
    _viewer: dict = Depends(require_viewer),
) -> ServiceCatalogResponse:
    from decnet.services.registry import all_services
    registry = all_services()
    return ServiceCatalogResponse(
        services=all_service_names(),
        fleet_singletons=[
            name for name, svc in registry.items() if svc.fleet_singleton
        ],
    )


@router.get(
    "/archetypes",
    tags=["MazeNET Topologies"],
    response_model=ArchetypeCatalogResponse,
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.topology.catalog.archetypes")
async def api_list_archetypes(
    _viewer: dict = Depends(require_viewer),
) -> ArchetypeCatalogResponse:
    return ArchetypeCatalogResponse(
        archetypes=[
            ArchetypeEntry(
                slug=a.slug,
                display_name=a.display_name,
                description=a.description,
                services=list(a.services),
                preferred_distros=list(a.preferred_distros),
                nmap_os=a.nmap_os,
            )
            for a in all_archetypes().values()
        ],
    )


@router.get(
    "/next-subnet",
    tags=["MazeNET Topologies"],
    response_model=NextSubnetResponse,
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Allocator exhausted"},
    },
)
@_traced("api.topology.catalog.next_subnet")
async def api_next_subnet(
    base: str = Query(
        default="172.16.0.0/12",
        pattern=r"^\d{1,3}\.\d{1,3}(\.\d{1,3}\.\d{1,3}/\d{1,2})?$",
    ),
    _viewer: dict = Depends(require_viewer),
) -> NextSubnetResponse:
    reserved = await reserved_subnets(repo)
    alloc = SubnetAllocator(base_prefix=base, reserved=reserved)
    try:
        subnet = alloc.next_free()
    except AllocatorExhausted as e:
        raise HTTPException(status_code=409, detail=str(e))
    return NextSubnetResponse(subnet=subnet)


@router.get(
    "/{topology_id}/lans/{lan_id}/next-ip",
    tags=["MazeNET Topologies"],
    response_model=NextIPResponse,
    responses={
        400: {"description": "Malformed path parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or LAN not found"},
        409: {"description": "Allocator exhausted"},
    },
)
@_traced("api.topology.catalog.next_ip")
async def api_next_ip(
    topology_id: str,
    lan_id: str,
    _viewer: dict = Depends(require_viewer),
) -> NextIPResponse:
    if await repo.get_topology(topology_id) is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    lans = await repo.list_lans_for_topology(topology_id)
    lan = next((ln for ln in lans if ln["id"] == lan_id), None)
    if lan is None:
        raise HTTPException(status_code=404, detail="LAN not found")
    deckies = await repo.list_topology_deckies(topology_id)
    alloc = IPAllocator(subnet=lan["subnet"])
    for d in deckies:
        ip = (d.get("decky_config") or {}).get("ips_by_lan", {}).get(lan["name"])
        if ip:
            try:
                alloc.reserve(ip)
            except ValueError:
                continue
    try:
        ip = alloc.next_free()
    except AllocatorExhausted as e:
        raise HTTPException(status_code=409, detail=str(e))
    return NextIPResponse(subnet=lan["subnet"], ip=ip)
