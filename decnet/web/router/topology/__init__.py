"""MazeNET topology REST endpoints (phase 3).

Thin FastAPI layer over the phase-2 topology machinery:
generate/validate/deploy/teardown, pending-only child CRUD, and the
live-mutation queue for active|degraded topologies.

Mounted at ``/api/v1/topologies`` by the main api router.  Sub-routers
live one-per-file and are aggregated here.
"""
from fastapi import APIRouter

from .api_catalog import router as _catalog_router
from .api_create_topology import router as _create_router
from .api_create_blank_topology import router as _create_blank_router
from .api_decky_crud import router as _decky_router
from .api_delete_topology import router as _delete_router
from .api_deploy_topology import router as _deploy_router
from .api_edge_crud import router as _edge_router
from .api_events import router as _events_router
from .api_get_topology import router as _get_router
from .api_lan_crud import router as _lan_router
from .api_list_topologies import router as _list_router
from .api_mutations import router as _mutations_router
from .api_teardown_topology import router as _teardown_router

topology_router = APIRouter(prefix="/topologies", tags=["topologies"])

# Order matters: catalog routes use literal path segments (e.g.
# /services, /next-subnet) that would otherwise be shadowed by the
# `/{topology_id}` path in api_get_topology.  Keep the catalog router
# included first so FastAPI's trie resolves literals before the
# parameterized fallback.
topology_router.include_router(_catalog_router)
topology_router.include_router(_list_router)
topology_router.include_router(_create_blank_router)
topology_router.include_router(_create_router)
topology_router.include_router(_deploy_router)
topology_router.include_router(_teardown_router)
topology_router.include_router(_delete_router)
topology_router.include_router(_lan_router)
topology_router.include_router(_decky_router)
topology_router.include_router(_edge_router)
topology_router.include_router(_mutations_router)
topology_router.include_router(_events_router)
topology_router.include_router(_get_router)


__all__ = ["topology_router"]
