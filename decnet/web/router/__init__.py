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
from .attackers.api_get_attackers import router as attackers_router
from .attackers.api_get_attacker_detail import router as attacker_detail_router
from .attackers.api_get_attacker_commands import router as attacker_commands_router
from .attackers.api_get_attacker_artifacts import router as attacker_artifacts_router
from .attackers.api_get_attacker_transcripts import router as attacker_transcripts_router
from .transcripts import transcripts_router
from .config.api_get_config import router as config_get_router
from .config.api_update_config import router as config_update_router
from .config.api_manage_users import router as config_users_router
from .config.api_reinit import router as config_reinit_router
from .health.api_get_health import router as health_router
from .workers.api_list_workers import router as workers_list_router
from .workers.api_control_worker import router as workers_control_router
from .workers.api_start_worker import router as workers_start_router
from .workers.api_start_all_workers import router as workers_start_all_router
from .artifacts.api_get_artifact import router as artifacts_router
from .swarm_updates import swarm_updates_router
from .swarm_mgmt import swarm_mgmt_router
from .system import system_router
from .topology import topology_router

api_router = APIRouter(
    # Every route under /api/v1 is auth-guarded (either by an explicit
    # require_* Depends or by the global auth middleware). Document 401/403
    # here so the OpenAPI schema reflects reality for contract tests.
    responses={
        400: {"description": "Malformed request body"},
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Authenticated but not authorized"},
        404: {"description": "Referenced resource does not exist"},
        409: {"description": "Conflict with existing resource"},
    },
)

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

# Attacker Profiles
api_router.include_router(attackers_router)
api_router.include_router(attacker_detail_router)
api_router.include_router(attacker_commands_router)
api_router.include_router(attacker_artifacts_router)
api_router.include_router(attacker_transcripts_router)

# Observability
api_router.include_router(stats_router)
api_router.include_router(stream_router)
api_router.include_router(health_router)
api_router.include_router(workers_list_router)
api_router.include_router(workers_control_router)
api_router.include_router(workers_start_router)
api_router.include_router(workers_start_all_router)

# Configuration
api_router.include_router(config_get_router)
api_router.include_router(config_update_router)
api_router.include_router(config_users_router)
api_router.include_router(config_reinit_router)

# Artifacts (captured attacker file drops)
api_router.include_router(artifacts_router)

# Transcripts (PTY session recordings, paged asciinema events)
api_router.include_router(transcripts_router)

# Remote Updates (dashboard → worker updater daemons)
api_router.include_router(swarm_updates_router)

# Swarm Management (dashboard: hosts, deckies, agent enrollment bundles)
api_router.include_router(swarm_mgmt_router)

# System info (deployment-mode auto-detection, etc.)
api_router.include_router(system_router)

# MazeNET Topologies (nested topology CRUD + mutation queue)
api_router.include_router(topology_router)
