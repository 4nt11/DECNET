"""POST /topologies/{id}/deploy — transition pending → deploying and fire
the background deploy.

The actual Docker work happens in a BackgroundTask so the HTTP caller
returns quickly with ``202 Accepted``.  Status transitions
(``deploying`` → ``active`` | ``failed``) are written by
:func:`decnet.engine.deployer.deploy_topology` itself.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from decnet.engine.deployer import deploy_topology
from decnet.telemetry import traced as _traced
from decnet.topology.status import TopologyStatus
from decnet.web.db.models import TopologySummary
from decnet.web.dependencies import repo, require_admin

log = logging.getLogger(__name__)

router = APIRouter()


async def _run_deploy(topology_id: str) -> None:
    """BackgroundTask body: deploy, swallow + log any exception so the
    task runner doesn't crash.  Status on failure is marked by
    :func:`deploy_topology` via its own exception handler.
    """
    try:
        await deploy_topology(repo, topology_id)
    except asyncio.CancelledError:  # pragma: no cover — shutdown
        raise
    except Exception as exc:  # noqa: BLE001
        from decnet.engine.deployer import _format_subprocess_error
        log.error(
            "background deploy of %s failed: %s",
            topology_id, _format_subprocess_error(exc),
        )


@router.post(
    "/{topology_id}/deploy",
    tags=["MazeNET Topologies"],
    response_model=TopologySummary,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "Malformed path parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "Topology is not in 'pending' status"},
    },
)
@_traced("api.topology.deploy")
async def api_deploy_topology(
    topology_id: str,
    background: BackgroundTasks,
    _admin: dict = Depends(require_admin),
) -> TopologySummary:
    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    if topo.status != TopologyStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Topology is {topo.status!r}; only 'pending' topologies "
                f"can be deployed."
            ),
        )

    background.add_task(_run_deploy, topology_id)
    return topo
