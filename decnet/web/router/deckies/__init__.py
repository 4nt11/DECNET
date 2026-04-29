"""Cross-cutting decky operation endpoints.

These routes apply to both fleet and MazeNET (topology) deckies; the
MazeNET case is selected by passing ``topology_id`` in the request body.

Compare with:

* :mod:`decnet.web.router.fleet` — fleet-only CRUD (deploy, mutate,
  list).
* :mod:`decnet.web.router.topology` — topology-only CRUD.
"""
from __future__ import annotations

from fastapi import APIRouter

from .api_file_drop import router as file_drop_router
from .api_services import (
    fleet_services_router,
    topology_services_router,
)

deckies_router = APIRouter()
deckies_router.include_router(file_drop_router)
deckies_router.include_router(fleet_services_router)
# Topology service routes live under /topologies/{id}/... — the prefix
# is set on the router itself.  Mounted under the same `deckies_router`
# umbrella because the *operation* (add/remove a service on a deployed
# decky) is identical; only the addressing scheme differs.
deckies_router.include_router(topology_services_router)

__all__ = ["deckies_router"]
