"""POST /topologies — generate and persist a new MazeNET topology."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.telemetry import traced as _traced
from decnet.topology.allocator import reserved_subnets
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist
from decnet.web.db.models import TopologyGenerateRequest, TopologySummary
from decnet.web.dependencies import repo, require_admin

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
        409: {"description": "Generator could not allocate subnets (exhausted pool)"},
    },
)
@_traced("api.topology.create")
async def api_create_topology(
    body: TopologyGenerateRequest,
    _admin: dict = Depends(require_admin),
) -> TopologySummary:
    try:
        config = TopologyConfig(
            name=body.name,
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

    topology_id = await persist(repo, plan)
    row = await repo.get_topology(topology_id)
    return TopologySummary(**row)
