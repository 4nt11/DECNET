# SPDX-License-Identifier: AGPL-3.0-or-later
"""DELETE /topologies/{id} — cascade-delete a pending or torn-down topology."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from decnet.telemetry import traced as _traced
from decnet.topology.status import TopologyStatus
from decnet.web.dependencies import repo, require_admin

router = APIRouter()

# Only allow delete when containers are guaranteed not to be running.
# ACTIVE / DEPLOYING / DEGRADED / TEARING_DOWN must teardown first.
_DELETABLE: frozenset[str] = frozenset(
    {TopologyStatus.PENDING, TopologyStatus.TORN_DOWN, TopologyStatus.FAILED}
)


@router.delete(
    "/{topology_id}",
    tags=["MazeNET Topologies"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"description": "Malformed path parameters"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "Topology has running resources; teardown first"},
    },
)
@_traced("api.topology.delete")
async def api_delete_topology(
    topology_id: str,
    _admin: dict = Depends(require_admin),
) -> Response:
    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    if topo.status not in _DELETABLE:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Topology is {topo.status!r}; teardown to 'torn_down' "
                f"before delete."
            ),
        )
    deleted = await repo.delete_topology_cascade(topology_id)
    if not deleted:
        # Race: row vanished between the status check and the cascade.
        raise HTTPException(status_code=404, detail="Topology not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
