"""Shared helpers for the Phase-3 child-CRUD routes."""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from decnet.topology.status import (
    TopologyNotEditable,
    TopologyStatus,
    VersionConflict,
)
from decnet.web.dependencies import repo


async def get_topology_or_404(topology_id: str) -> dict[str, Any]:
    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    return topo


async def assert_pending_or_409(topology_id: str) -> dict[str, Any]:
    """Ensure the topology exists and is in ``pending`` state.

    The repo layer enforces the same rule inside mutation methods, but the
    ``add_*`` helpers don't — re-check here so every write route agrees on
    the pre-condition before any side effect.
    """
    topo = await get_topology_or_404(topology_id)
    if topo["status"] != TopologyStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Topology is {topo['status']!r}; free-form child edits are "
                f"pending-only.  Use the mutation queue for active topologies."
            ),
        )
    return topo


def map_repo_exception(exc: Exception) -> HTTPException:
    """Translate repo-layer exceptions to HTTP status codes."""
    if isinstance(exc, TopologyNotEditable):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, VersionConflict):
        return HTTPException(
            status_code=409,
            detail=f"Version conflict: expected {exc.expected}, current {exc.current}",
        )
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")
