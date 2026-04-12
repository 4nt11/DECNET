from fastapi import APIRouter

from .auth.api_login import router as login_router
from .auth.api_change_pass import router as change_pass_router
from .logs.api_get_logs import router as logs_router
from .logs.api_get_histogram import router as histogram_router
from .bounty.api_get_bounties import router as bounty_router
from .stats.api_get_stats import router as stats_router
from .fleet.api_get_deckies import router as get_deckies_router
from .fleet.api_mutate_decky import router as mutate_decky_router
from .fleet.api_mutate_interval import router as mutate_interval_router
from .fleet.api_deploy_deckies import router as deploy_deckies_router
from .stream.api_stream_events import router as stream_router

api_router = APIRouter()

# Authentication
api_router.include_router(login_router)
api_router.include_router(change_pass_router)

# Logs & Analytics
api_router.include_router(logs_router)
api_router.include_router(histogram_router)

# Bounty Vault
api_router.include_router(bounty_router)

# Fleet Management
api_router.include_router(get_deckies_router)
api_router.include_router(mutate_decky_router)
api_router.include_router(mutate_interval_router)
api_router.include_router(deploy_deckies_router)

# Observability
api_router.include_router(stats_router)
api_router.include_router(stream_router)
