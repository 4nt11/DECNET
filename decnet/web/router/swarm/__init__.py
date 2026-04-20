"""Swarm controller routers.

One file per endpoint, aggregated under the ``/swarm`` prefix. Mounted
onto the swarm-api FastAPI app (``decnet/web/swarm_api.py``), a separate
process from the main DECNET API so swarm failures cannot cascade into
log ingestion / dashboard serving.
"""
from fastapi import APIRouter

from .api_enroll_host import router as enroll_host_router
from .api_list_hosts import router as list_hosts_router
from .api_get_host import router as get_host_router
from .api_decommission_host import router as decommission_host_router
from .api_deploy_swarm import router as deploy_swarm_router
from .api_teardown_swarm import router as teardown_swarm_router
from .api_get_swarm_health import router as get_swarm_health_router
from .api_check_hosts import router as check_hosts_router
from .api_heartbeat import router as heartbeat_router
from .api_list_deckies import router as list_deckies_router

swarm_router = APIRouter(prefix="/swarm")

# Hosts
swarm_router.include_router(enroll_host_router)
swarm_router.include_router(list_hosts_router)
swarm_router.include_router(get_host_router)
swarm_router.include_router(decommission_host_router)

# Deployments
swarm_router.include_router(deploy_swarm_router)
swarm_router.include_router(teardown_swarm_router)
swarm_router.include_router(list_deckies_router)

# Health
swarm_router.include_router(get_swarm_health_router)
swarm_router.include_router(check_hosts_router)
swarm_router.include_router(heartbeat_router)
