"""Swarm management endpoints for the React dashboard.

These are *not* the unauthenticated /swarm routes mounted on the separate
swarm-controller process (decnet/web/swarm_api.py on port 8770). These
live on the main web API, go through ``require_admin``, and are the
interface the dashboard uses to list hosts, decommission them, list
deckies across the fleet, and generate one-shot agent-enrollment
bundles.

Mounted under ``/api/v1/swarm`` by the main api router.
"""
from fastapi import APIRouter

from .api_list_hosts import router as list_hosts_router
from .api_decommission_host import router as decommission_host_router
from .api_list_deckies import router as list_deckies_router
from .api_enroll_bundle import router as enroll_bundle_router
from .api_teardown_host import router as teardown_host_router

swarm_mgmt_router = APIRouter(prefix="/swarm")

swarm_mgmt_router.include_router(list_hosts_router)
swarm_mgmt_router.include_router(decommission_host_router)
swarm_mgmt_router.include_router(list_deckies_router)
swarm_mgmt_router.include_router(enroll_bundle_router)
swarm_mgmt_router.include_router(teardown_host_router)
