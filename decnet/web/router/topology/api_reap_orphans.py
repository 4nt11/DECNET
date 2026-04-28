"""POST /topologies/reap-orphans — remove Docker resources for topology
ids the DB no longer knows about.

A topology row deleted outside the teardown flow (operator error,
crashed master, direct DB edit) leaves its containers and bridge
networks behind. The orphan networks keep their IPAM pools, so the
next deploy at the same subnet hits a 403 ``Pool overlaps`` from the
Docker daemon.

This endpoint walks the local Docker daemon, computes the set of
topology prefixes still known to the repo, and force-removes every
container + network whose prefix is orphaned. Resources belonging to
live topologies are never touched.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from decnet.engine.reaper import reap_orphan_topology_resources
from decnet.telemetry import traced as _traced
from decnet.web.db.models import ReapReportResponse
from decnet.web.dependencies import repo, require_admin

router = APIRouter()


@router.post(
    "/reap-orphans",
    tags=["MazeNET Topologies"],
    response_model=ReapReportResponse,
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.topology.reap_orphans")
async def api_reap_orphans(
    _admin: dict = Depends(require_admin),
) -> dict:
    """Reap Docker resources whose topology id is absent from the DB.

    Returns a report with the live prefixes, the orphan prefixes that
    were identified, every container + network actually removed, and
    any per-resource errors encountered. Errors are non-fatal — a
    single stuck resource does not abort the sweep.
    """
    report = await reap_orphan_topology_resources(repo)
    return report.to_dict()
