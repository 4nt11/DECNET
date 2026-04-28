"""POST /topologies — generate and persist a new MazeNET topology."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError

from decnet.telemetry import traced as _traced
from decnet.topology.allocator import reserved_subnets
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist
from decnet.web.db.models import TopologyGenerateRequest, TopologySummary
from decnet.web.dependencies import repo, require_admin
from decnet.web.router.topology._target_host import validate_target_host

router = APIRouter()


@router.post(
    "/",
    tags=["MazeNET Topologies"],
    response_model=TopologySummary,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "Malformed or invalid generation parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Duplicate topology name, or generator could not allocate subnets (exhausted pool)"},
    },
)
@_traced("api.topology.create")
async def api_create_topology(
    body: TopologyGenerateRequest,
    _admin: dict = Depends(require_admin),
) -> TopologySummary:
    await validate_target_host(repo, body.mode, body.target_host_uuid)
    try:
        config = TopologyConfig(
            name=body.name,
            mode=body.mode,
            depth=body.depth,
            branching_factor=body.branching_factor,
            deckies_per_lan_min=body.deckies_per_lan_min,
            deckies_per_lan_max=body.deckies_per_lan_max,
            bridge_forward_probability=body.bridge_forward_probability,
            cross_edge_probability=body.cross_edge_probability,
            services_explicit=body.services_explicit,
            randomize_services=body.randomize_services,
            seed=body.seed,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        plan = generate(config, reserved_subnets=await reserved_subnets(repo))
    except RuntimeError as exc:
        # Subnet allocator exhaustion or similar planner-level failure.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        topology_id = await persist(repo, plan, target_host_uuid=body.target_host_uuid)
    except IntegrityError as exc:
        # Unique constraint on topologies.name is the only integrity
        # error the create path can realistically hit — inspecting the
        # constraint name keeps us from silently mapping unrelated
        # integrity failures to 409.
        msg = str(exc.orig) if exc.orig is not None else str(exc)
        if "ix_topologies_name" in msg or "topologies.name" in msg:
            raise HTTPException(
                status_code=409,
                detail=f"A topology named {body.name!r} already exists.",
            ) from exc
        raise
    row = await repo.get_topology(topology_id)
    return TopologySummary(**row)
