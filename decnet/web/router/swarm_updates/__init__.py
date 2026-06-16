# SPDX-License-Identifier: AGPL-3.0-or-later
"""Remote Updates — master dashboard's surface for pushing code to workers.

These are *not* the swarm-controller's /swarm routes (those run on a
separate process, auth-free, internal-only). They live on the main web
API, go through ``require_admin``, and are the interface the React
dashboard calls to fan updates out to worker ``decnet updater`` daemons
via ``UpdaterClient``.

Mounted under ``/api/v1/swarm-updates`` by the main api router.
"""
from fastapi import APIRouter

from .api_list_host_releases import router as list_host_releases_router
from .api_push_update import router as push_update_router
from .api_push_update_self import router as push_update_self_router
from .api_rollback_host import router as rollback_host_router

swarm_updates_router = APIRouter(prefix="/swarm-updates")

swarm_updates_router.include_router(list_host_releases_router)
swarm_updates_router.include_router(push_update_router)
swarm_updates_router.include_router(push_update_self_router)
swarm_updates_router.include_router(rollback_host_router)
