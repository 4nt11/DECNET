"""MazeNET topology REST endpoints (phase 3).

Thin FastAPI layer over the phase-2 topology machinery:
generate/validate/deploy/teardown, pending-only child CRUD, and the
live-mutation queue for active|degraded topologies.

Mounted at ``/api/v1/topologies`` by the main api router.  Sub-routers
live one-per-file and are aggregated here.
"""
from fastapi import APIRouter

topology_router = APIRouter(prefix="/topologies", tags=["topologies"])

# Sub-routers land in later steps; this skeleton keeps the package
# import-safe so the main api router can mount it immediately.


__all__ = ["topology_router"]
