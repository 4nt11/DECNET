"""POST/DELETE …/{decky}/services — live service add/remove.

Two scopes mounted here:

* fleet:    ``/api/v1/deckies/{decky_name}/services``
* topology: ``/api/v1/topologies/{topology_id}/deckies/{decky_name}/services``

Both return the post-mutation services list so the dashboard can
re-render without a follow-up GET.

Auth: ``require_admin`` everywhere (matches every other write op on
deckies — see :mod:`decnet.web.router.fleet.api_mutate_decky`).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path

from decnet.engine.services_live import (
    ServiceMutationError,
    add_service,
    remove_service,
    update_service_config,
)
from decnet.logging import get_logger
from decnet.services.base import ConfigValidationError
from decnet.web.db.models import (
    DeckyServiceAddRequest,
    DeckyServiceConfigRequest,
    DeckyServiceConfigResponse,
    DeckyServicesResponse,
)
from decnet.web.dependencies import repo, require_admin

log = get_logger("api.deckies.services")


fleet_services_router = APIRouter(tags=["Deckies"])
topology_services_router = APIRouter(prefix="/topologies", tags=["Deckies"])


def _map_mutation_error(exc: ServiceMutationError) -> HTTPException:
    """Translate engine-layer errors into 4xx codes.

    Three cases the API reasonably distinguishes:

    * ``not found`` (decky / topology missing) → 404
    * ``already on`` / ``not on`` (idempotency violation) → 409
    * everything else (unknown service, fleet_singleton) → 422
    """
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=404, detail=msg)
    if "already on" in msg or "not on" in msg:
        return HTTPException(status_code=409, detail=msg)
    return HTTPException(status_code=422, detail=msg)


# ---------------------------------------------------------- fleet

@fleet_services_router.post(
    "/deckies/{decky_name}/services",
    response_model=DeckyServicesResponse,
    responses={
        400: {"description": "Malformed request body or initial config rejected by service schema"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found"},
        409: {"description": "Service already on decky"},
        422: {"description": "Unknown or fleet_singleton service"},
    },
)
async def api_fleet_add_service(
    req: DeckyServiceAddRequest,
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServicesResponse:
    try:
        services = await add_service(
            repo, decky_kind="fleet",
            decky_name=decky_name, service_name=req.name,
            config=req.config,
        )
    except ConfigValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ServiceMutationError as exc:
        raise _map_mutation_error(exc) from exc
    return DeckyServicesResponse(decky_name=decky_name, services=services)


async def _do_update_config(
    *, decky_kind, decky_name, service_name, cfg, apply, topology_id=None,
) -> DeckyServiceConfigResponse:
    try:
        validated = await update_service_config(
            repo,
            decky_kind=decky_kind,
            decky_name=decky_name,
            service_name=service_name,
            cfg=cfg,
            apply=apply,
            topology_id=topology_id,
        )
    except ConfigValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ServiceMutationError as exc:
        raise _map_mutation_error(exc) from exc
    return DeckyServiceConfigResponse(
        decky_name=decky_name,
        service_name=service_name,
        topology_id=topology_id,
        config=validated,
        recreated=apply,
    )


@fleet_services_router.put(
    "/deckies/{decky_name}/services/{service_name}/config",
    response_model=DeckyServiceConfigResponse,
    responses={
        400: {"description": "Config rejected by service schema"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found"},
        409: {"description": "Service not on decky"},
        422: {"description": "Unknown service"},
    },
)
async def api_fleet_put_service_config(
    req: DeckyServiceConfigRequest,
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    service_name: str = Path(..., pattern=r"^[a-z0-9_\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServiceConfigResponse:
    """Persist new service_config (DB + compose); container untouched."""
    return await _do_update_config(
        decky_kind="fleet",
        decky_name=decky_name,
        service_name=service_name,
        cfg=req.config,
        apply=False,
    )


@fleet_services_router.post(
    "/deckies/{decky_name}/services/{service_name}/apply",
    response_model=DeckyServiceConfigResponse,
    responses={
        400: {"description": "Config rejected by service schema"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found"},
        409: {"description": "Service not on decky"},
        422: {"description": "Unknown service"},
    },
)
async def api_fleet_apply_service_config(
    req: DeckyServiceConfigRequest,
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    service_name: str = Path(..., pattern=r"^[a-z0-9_\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServiceConfigResponse:
    """Persist + force-recreate that one service container.  Destructive."""
    return await _do_update_config(
        decky_kind="fleet",
        decky_name=decky_name,
        service_name=service_name,
        cfg=req.config,
        apply=True,
    )


@fleet_services_router.delete(
    "/deckies/{decky_name}/services/{service_name}",
    response_model=DeckyServicesResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found"},
        409: {"description": "Service not on decky"},
    },
)
async def api_fleet_remove_service(
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    service_name: str = Path(..., pattern=r"^[a-z0-9_\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServicesResponse:
    try:
        services = await remove_service(
            repo, decky_kind="fleet",
            decky_name=decky_name, service_name=service_name,
        )
    except ServiceMutationError as exc:
        raise _map_mutation_error(exc) from exc
    return DeckyServicesResponse(decky_name=decky_name, services=services)


# ---------------------------------------------------------- topology

@topology_services_router.post(
    "/{topology_id}/deckies/{decky_name}/services",
    response_model=DeckyServicesResponse,
    responses={
        400: {"description": "Malformed request body or initial config rejected by service schema"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or decky not found"},
        409: {"description": "Service already on decky"},
        422: {"description": "Unknown or fleet_singleton service"},
    },
)
async def api_topology_add_service(
    req: DeckyServiceAddRequest,
    topology_id: str = Path(...),
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServicesResponse:
    try:
        services = await add_service(
            repo, decky_kind="topology", topology_id=topology_id,
            decky_name=decky_name, service_name=req.name,
            config=req.config,
        )
    except ConfigValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ServiceMutationError as exc:
        raise _map_mutation_error(exc) from exc
    return DeckyServicesResponse(
        decky_name=decky_name, topology_id=topology_id, services=services,
    )


@topology_services_router.put(
    "/{topology_id}/deckies/{decky_name}/services/{service_name}/config",
    response_model=DeckyServiceConfigResponse,
    responses={
        400: {"description": "Config rejected by service schema"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or decky not found"},
        409: {"description": "Service not on decky"},
        422: {"description": "Unknown service"},
    },
)
async def api_topology_put_service_config(
    req: DeckyServiceConfigRequest,
    topology_id: str = Path(...),
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    service_name: str = Path(..., pattern=r"^[a-z0-9_\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServiceConfigResponse:
    return await _do_update_config(
        decky_kind="topology",
        topology_id=topology_id,
        decky_name=decky_name,
        service_name=service_name,
        cfg=req.config,
        apply=False,
    )


@topology_services_router.post(
    "/{topology_id}/deckies/{decky_name}/services/{service_name}/apply",
    response_model=DeckyServiceConfigResponse,
    responses={
        400: {"description": "Config rejected by service schema"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or decky not found"},
        409: {"description": "Service not on decky"},
        422: {"description": "Unknown service"},
    },
)
async def api_topology_apply_service_config(
    req: DeckyServiceConfigRequest,
    topology_id: str = Path(...),
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    service_name: str = Path(..., pattern=r"^[a-z0-9_\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServiceConfigResponse:
    return await _do_update_config(
        decky_kind="topology",
        topology_id=topology_id,
        decky_name=decky_name,
        service_name=service_name,
        cfg=req.config,
        apply=True,
    )


@topology_services_router.delete(
    "/{topology_id}/deckies/{decky_name}/services/{service_name}",
    response_model=DeckyServicesResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology or decky not found"},
        409: {"description": "Service not on decky"},
    },
)
async def api_topology_remove_service(
    topology_id: str = Path(...),
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    service_name: str = Path(..., pattern=r"^[a-z0-9_\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> DeckyServicesResponse:
    try:
        services = await remove_service(
            repo, decky_kind="topology", topology_id=topology_id,
            decky_name=decky_name, service_name=service_name,
        )
    except ServiceMutationError as exc:
        raise _map_mutation_error(exc) from exc
    return DeckyServicesResponse(
        decky_name=decky_name, topology_id=topology_id, services=services,
    )
