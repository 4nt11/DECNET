"""POST /topologies/{id}/teardown — transition an active/degraded/failed
topology to ``tearing_down`` and fire the background teardown.

Mirrors :mod:`api_deploy_topology`: the real Docker work runs in a
BackgroundTask, the caller returns ``202 Accepted``, and
:func:`decnet.engine.deployer.teardown_topology` writes the terminal
``torn_down`` status when it finishes.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from decnet.engine.deployer import teardown_topology
from decnet.telemetry import traced as _traced
from decnet.topology.status import TopologyStatus
from decnet.web.db.models import TopologySummary
from decnet.web.dependencies import repo, require_admin

log = logging.getLogger(__name__)

router = APIRouter()

# Statuses that can legally transition to TEARING_DOWN (see
# decnet.topology.status._LEGAL).
_TEARDOWNABLE: frozenset[str] = frozenset(
    {
        TopologyStatus.ACTIVE,
        TopologyStatus.DEGRADED,
        TopologyStatus.FAILED,
        TopologyStatus.DEPLOYING,
    }
)


async def _run_teardown(topology_id: str) -> None:
    try:
        await teardown_topology(repo, topology_id)
    except asyncio.CancelledError:  # pragma: no cover — shutdown
        raise
    except Exception as exc:  # noqa: BLE001
        log.error("background teardown of %s failed: %s", topology_id, exc)


@router.post(
    "/{topology_id}/teardown",
    tags=["MazeNET Topologies"],
    response_model=TopologySummary,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "Malformed path parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "Topology cannot be torn down from its current status"},
    },
)
@_traced("api.topology.teardown")
async def api_teardown_topology(
    topology_id: str,
    background: BackgroundTasks,
    _admin: dict = Depends(require_admin),
) -> TopologySummary:
    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    if topo.status not in _TEARDOWNABLE:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Topology is {topo.status!r}; cannot teardown "
                f"(allowed from: {sorted(_TEARDOWNABLE)})."
            ),
        )

    background.add_task(_run_teardown, topology_id)
    return TopologySummary(**topo)
