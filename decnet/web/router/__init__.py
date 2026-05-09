from fastapi import APIRouter

from .auth.api_login import router as login_router
from .auth.api_change_pass import router as change_pass_router
from .logs.api_get_logs import router as logs_router
from .logs.api_get_histogram import router as histogram_router
from .bounty.api_get_bounties import router as bounty_router
from .credentials.api_get_credentials import router as credentials_router
from .credential_reuse.api_get_credential_reuse import router as credential_reuse_router
from .stats.api_get_stats import router as stats_router
from .fleet.api_get_deckies import router as get_deckies_router
from .fleet.api_mutate_decky import router as mutate_decky_router
from .fleet.api_mutate_interval import router as mutate_interval_router
from .fleet.api_deploy_deckies import router as deploy_deckies_router
from .stream.api_stream_events import router as stream_router
from .attackers.api_get_attackers import router as attackers_router
from .attackers.api_export_attackers import router as attackers_export_router
from .attackers.api_events import router as attacker_events_router
from .attackers.api_get_attacker_detail import router as attacker_detail_router
from .attackers.api_get_attacker_commands import router as attacker_commands_router
from .attackers.api_get_attacker_artifacts import router as attacker_artifacts_router
from .attackers.api_get_attacker_transcripts import router as attacker_transcripts_router
from .attackers.api_get_attacker_smtp_targets import router as attacker_smtp_targets_router
from .attackers.api_get_attacker_mail import router as attacker_mail_router
from .attackers.api_get_attacker_intel import router as attacker_intel_router
from .identities.api_list_identities import router as identities_list_router
from .identities.api_get_identity_detail import router as identity_detail_router
from .identities.api_list_identity_observations import router as identity_observations_router
from .identities.api_events import router as identity_events_router
from .campaigns.api_list_campaigns import router as campaigns_list_router
from .campaigns.api_get_campaign_detail import router as campaign_detail_router
from .campaigns.api_list_campaign_identities import router as campaign_identities_router
from .campaigns.api_events import router as campaign_events_router
from .orchestrator.api_list_events import router as orchestrator_list_router
from .orchestrator.api_events import router as orchestrator_events_router
from .orchestrator.api_event_stats import router as orchestrator_stats_router
from .realism.api_config import router as realism_config_router
from .realism.api_personas import router as realism_personas_router
from .realism.api_synthetic_files import router as realism_synthetic_files_router
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
from .canary import canary_router
from .deckies import deckies_router
from .webhooks import webhooks_router
from .ttp.api_get_techniques import router as ttp_techniques_router
from .ttp.api_get_by_identity import router as ttp_by_identity_router
from .ttp.api_get_by_attacker import router as ttp_by_attacker_router
from .ttp.api_get_by_campaign import router as ttp_by_campaign_router
from .ttp.api_get_by_session import router as ttp_by_session_router
from .ttp.api_get_rules import router as ttp_rules_router
from .ttp.api_get_tag_details import router as ttp_tag_details_router
from .ttp.api_export_navigator import router as ttp_navigator_router

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

# Credentials (deduped attacker auth attempts)
api_router.include_router(credentials_router)

# Credential reuse findings (cross-decky/cross-service same-secret hits)
api_router.include_router(credential_reuse_router)

# Fleet Management
api_router.include_router(get_deckies_router)
api_router.include_router(mutate_decky_router)
api_router.include_router(mutate_interval_router)
api_router.include_router(deploy_deckies_router)

# Attacker Profiles
api_router.include_router(attackers_router)
api_router.include_router(attackers_export_router)
api_router.include_router(attacker_detail_router)
api_router.include_router(attacker_events_router)
api_router.include_router(attacker_commands_router)
api_router.include_router(attacker_artifacts_router)
api_router.include_router(attacker_transcripts_router)
api_router.include_router(attacker_smtp_targets_router)
api_router.include_router(attacker_mail_router)
api_router.include_router(attacker_intel_router)

# Identity Resolution (read-only; populated by the clusterer worker —
# see development/IDENTITY_RESOLUTION.md). Empty until the clusterer
# ships; the API surface lands first so frontend + downstream work
# can target a stable shape.
api_router.include_router(identities_list_router)
api_router.include_router(identity_detail_router)
api_router.include_router(identity_observations_router)
api_router.include_router(identity_events_router)
api_router.include_router(campaigns_list_router)
api_router.include_router(campaign_detail_router)
api_router.include_router(campaign_identities_router)
api_router.include_router(campaign_events_router)
api_router.include_router(orchestrator_list_router)
api_router.include_router(orchestrator_events_router)
api_router.include_router(orchestrator_stats_router)

# Realism — global persona pool CRUD for the dashboard's
# "Persona Generation" page.  The orchestrator reads from the same
# on-disk JSON file directly (see decnet.realism.personas_pool).
api_router.include_router(realism_personas_router)
api_router.include_router(realism_synthetic_files_router)
api_router.include_router(realism_config_router)

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

# Canary tokens — operator-facing CRUD (worker hosts the
# attacker-facing surface separately via `decnet canary`).
api_router.include_router(canary_router)
api_router.include_router(deckies_router)

# External webhook subscriptions (SIEM/SOAR egress)
api_router.include_router(webhooks_router)

# TTP Tagging — see development/TTP_TAGGING.md. Contract phase: every
# handler returns the typed empty value; impl phase wires the repo
# and rule engine.
api_router.include_router(ttp_techniques_router)
api_router.include_router(ttp_by_identity_router)
api_router.include_router(ttp_by_attacker_router)
api_router.include_router(ttp_by_campaign_router)
api_router.include_router(ttp_by_session_router)
api_router.include_router(ttp_rules_router)
api_router.include_router(ttp_tag_details_router)
api_router.include_router(ttp_navigator_router)
