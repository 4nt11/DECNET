"""Live-mutation queue endpoints — for active | degraded topologies.

    POST /topologies/{id}/mutations   enqueue one mutation op
    GET  /topologies/{id}/mutations   list queued / applied / failed rows

The mutator worker claims pending rows via ``claim_next_mutation`` and
transitions them to ``applying`` → ``applied`` | ``failed``.  The API
layer only stages rows and reports them back.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from decnet.bus import topics as _topics
from decnet.bus.app import get_app_bus
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.topology.status import (
    TopologyStatus,
    VersionConflict,
)
from decnet.web.db.models import (
    MutationEnqueueRequest,
    MutationEnqueueResponse,
    MutationRow,
)
from decnet.web.dependencies import repo, require_admin, require_viewer

from ._guards import get_topology_or_404, map_repo_exception

_log = get_logger("api.topology.mutations")

router = APIRouter()

_MUTATABLE: frozenset[str] = frozenset(
    {TopologyStatus.ACTIVE, TopologyStatus.DEGRADED}
)


@router.post(
    "/{topology_id}/mutations",
    tags=["MazeNET Topologies"],
    response_model=MutationEnqueueResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "Malformed body or unknown mutation op"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {
            "description": (
                "Topology is not active|degraded, or version conflict"
            )
        },
    },
)
@_traced("api.topology.mutation.enqueue")
async def api_enqueue_mutation(
    topology_id: str,
    body: MutationEnqueueRequest,
    _admin: dict = Depends(require_admin),
) -> MutationEnqueueResponse:
    topo = await get_topology_or_404(topology_id)
    if topo.status not in _MUTATABLE:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Topology is {topo.status!r}; the mutation queue is "
                f"only open for 'active' or 'degraded' topologies.  Use "
                f"child-CRUD endpoints while pending."
            ),
        )

    try:
        mutation_id = await repo.enqueue_topology_mutation(
            topology_id,
            body.op,
            body.payload,
            expected_version=body.expected_version,
        )
    except VersionConflict as exc:
        raise map_repo_exception(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Fire-and-forget bus publish so the mutator can wake immediately and
    # the SSE route can notify connected editors.  Bus failure here must
    # never mask a successful enqueue — the DB row is authoritative.
    bus = await get_app_bus()
    if bus is not None:
        try:
            await bus.publish(
                _topics.topology_mutation(topology_id, _topics.MUTATION_ENQUEUED),
                {"mutation_id": mutation_id, "op": body.op, "payload": body.payload},
                event_type=_topics.MUTATION_ENQUEUED,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("bus publish (enqueued) failed: %s", exc)

    return MutationEnqueueResponse(mutation_id=mutation_id, state="pending")


@router.get(
    "/{topology_id}/mutations",
    tags=["MazeNET Topologies"],
    response_model=list[MutationRow],
    responses={
        400: {"description": "Malformed query parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
    },
)
@_traced("api.topology.mutation.list")
async def api_list_mutations(
    topology_id: str,
    state: Optional[str] = Query(
        default=None,
        description="Filter by state: pending | applying | applied | failed",
    ),
    _viewer: dict = Depends(require_viewer),
) -> list[MutationRow]:
    await get_topology_or_404(topology_id)
    rows = await repo.list_topology_mutations(topology_id, state=state)
    return [MutationRow(**r) for r in rows]
