# SPDX-License-Identifier: AGPL-3.0-or-later
from fastapi import APIRouter

from .api_deployment_mode import router as deployment_mode_router

system_router = APIRouter(prefix="/system", tags=["System"])
system_router.include_router(deployment_mode_router)
