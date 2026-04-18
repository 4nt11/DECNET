"""Swarm controller routers.

Mounted onto the swarm-api FastAPI app under the ``/swarm`` prefix. The
controller is a separate process from the main DECNET API so swarm
failures cannot cascade into log ingestion / dashboard serving.
"""
from fastapi import APIRouter

from .hosts import router as hosts_router
from .deployments import router as deployments_router
from .health import router as health_router

swarm_router = APIRouter(prefix="/swarm")
swarm_router.include_router(hosts_router)
swarm_router.include_router(deployments_router)
swarm_router.include_router(health_router)
