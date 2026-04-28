# FastAPI /api/v1 Route Audit Report

## Executive Summary

**Total Routes Analyzed**: 77
**Deletion Candidates**: 54
  - **Zero Callers (dead code)**: 7
  - **Test-Only (replaced routes?)**: 47

The audit scanned:
- 77 registered `/api/v1/*` routes across the FastAPI web application
- All sources: frontend TypeScript/React, CLI, worker processes, and test suites
- Frontend path fragment matching (e.g., searching for `/topologies/` in dynamic URLs)

**Top Deletion Candidates for Review**:
- Attacker detail endpoints (`/attackers/{uuid}*`) — 5 test-only routes, no web/CLI callers
- Decky mutation endpoints (`/deckies/{decky_name}/mutate*`) — 2 zero-caller routes (likely replaced by mutation queue)
- Various CRUD endpoints with test-only usage — likely superseded by newer flows

---

## Full Route Inventory

| Method | Path | Handler | File | Caller Types | Notes |
|--------|------|---------|------|--------------|-------|
| GET | `/` | `api_list_topologies()` | api_list_topologies.py | cli, test |  |
| POST | `/` | `api_create_topology()` | api_create_topology.py | cli, test |  |
| GET | `/archetypes` | `api_list_archetypes()` | api_catalog.py | **NONE** | ⚠️  |
| GET | `/artifacts/{decky}/{stored_as}` | `get_artifact()` | api_get_artifact.py | test | ⚠️  |
| GET | `/attackers` | `get_attackers()` | api_get_attackers.py | test, web |  |
| GET | `/attackers/{uuid}` | `get_attacker_detail()` | api_get_attacker_detail.py | test | ⚠️  |
| GET | `/attackers/{uuid}/artifacts` | `get_attacker_artifacts()` | api_get_attacker_artifacts.py | test | ⚠️  |
| GET | `/attackers/{uuid}/commands` | `get_attacker_commands()` | api_get_attacker_commands.py | test | ⚠️  |
| GET | `/attackers/{uuid}/transcripts` | `get_attacker_transcripts()` | api_get_attacker_transcripts.py | test | ⚠️  |
| POST | `/auth/change-password` | `change_password()` | api_change_pass.py | test | ⚠️  |
| POST | `/auth/login` | `login()` | api_login.py | test | ⚠️  |
| POST | `/blank` | `api_create_blank_topology()` | api_create_blank_topology.py | test | ⚠️  |
| GET | `/bounty` | `get_bounties()` | api_get_bounties.py | test | ⚠️  |
| POST | `/check` | `api_check_hosts()` | api_check_hosts.py | cli, test |  |
| GET | `/config` | `api_get_config()` | api_get_config.py | cli, test, web |  |
| PUT | `/config/deployment-limit` | `api_update_deployment_limit()` | api_update_config.py | test, web |  |
| PUT | `/config/global-mutation-interval` | `api_update_global_mutation_interval()` | api_update_config.py | test, web |  |
| DELETE | `/config/reinit` | `api_reinit()` | api_reinit.py | test, web |  |
| POST | `/config/users` | `api_create_user()` | api_manage_users.py | test, web |  |
| DELETE | `/config/users/{user_uuid}` | `api_delete_user()` | api_manage_users.py | test | ⚠️  |
| PUT | `/config/users/{user_uuid}/reset-password` | `api_reset_user_password()` | api_manage_users.py | test | ⚠️  |
| PUT | `/config/users/{user_uuid}/role` | `api_update_user_role()` | api_manage_users.py | test | ⚠️  |
| GET | `/deckies` | `get_deckies()` | api_get_deckies.py | cli, test, web |  |
| GET | `/deckies` | `api_list_deckies()` | api_list_deckies.py | cli, test, web |  |
| GET | `/deckies` | `list_deckies()` | api_list_deckies.py | cli, test, web |  |
| POST | `/deckies/deploy` | `api_deploy_deckies()` | api_deploy_deckies.py | test, web |  |
| POST | `/deckies/{decky_name}/mutate` | `api_mutate_decky()` | api_mutate_decky.py | **NONE** | ⚠️  |
| PUT | `/deckies/{decky_name}/mutate-interval` | `api_update_mutate_interval()` | api_mutate_interval.py | **NONE** | ⚠️  |
| POST | `/deploy` | `api_deploy_swarm()` | api_deploy_swarm.py | cli, test |  |
| GET | `/deployment-mode` | `get_deployment_mode()` | api_deployment_mode.py | test | ⚠️  |
| POST | `/enroll` | `api_enroll_host()` | api_enroll_host.py | cli, test |  |
| POST | `/enroll-bundle` | `create_enroll_bundle()` | api_enroll_bundle.py | test | ⚠️  |
| GET | `/enroll-bundle/{token}.sh` | `get_bootstrap()` | api_enroll_bundle.py | test | ⚠️  |
| GET | `/enroll-bundle/{token}.tgz` | `get_payload()` | api_enroll_bundle.py | test | ⚠️  |
| GET | `/health` | `get_health()` | api_get_health.py | cli, test |  |
| GET | `/health` | `api_get_swarm_health()` | api_get_swarm_health.py | cli, test |  |
| POST | `/heartbeat` | `heartbeat()` | api_heartbeat.py | test | ⚠️  |
| GET | `/hosts` | `api_list_hosts()` | api_list_hosts.py | cli, test |  |
| GET | `/hosts` | `list_hosts()` | api_list_hosts.py | cli, test |  |
| GET | `/hosts` | `api_list_host_releases()` | api_list_host_releases.py | cli, test |  |
| DELETE | `/hosts/{uuid}` | `api_decommission_host()` | api_decommission_host.py | test | ⚠️  |
| DELETE | `/hosts/{uuid}` | `decommission_host()` | api_decommission_host.py | test | ⚠️  |
| GET | `/hosts/{uuid}` | `api_get_host()` | api_get_host.py | test | ⚠️  |
| POST | `/hosts/{uuid}/teardown` | `teardown_host()` | api_teardown_host.py | test | ⚠️  |
| GET | `/logs` | `get_logs()` | api_get_logs.py | test | ⚠️  |
| GET | `/logs/histogram` | `get_logs_histogram()` | api_get_histogram.py | test | ⚠️  |
| GET | `/next-subnet` | `api_next_subnet()` | api_catalog.py | test | ⚠️  |
| POST | `/push` | `api_push_update()` | api_push_update.py | test | ⚠️  |
| POST | `/push-self` | `api_push_update_self()` | api_push_update_self.py | test | ⚠️  |
| POST | `/reap-orphans` | `api_reap_orphans()` | api_reap_orphans.py | test | ⚠️  |
| POST | `/rollback` | `api_rollback_host()` | api_rollback_host.py | test | ⚠️  |
| GET | `/services` | `api_list_services()` | api_catalog.py | test | ⚠️  |
| GET | `/stats` | `get_stats()` | api_get_stats.py | test | ⚠️  |
| GET | `/stream` | `stream_events()` | api_stream_events.py | test, web |  |
| POST | `/teardown` | `api_teardown_swarm()` | api_teardown_swarm.py | test | ⚠️  |
| GET | `/transcripts/{decky}/{sid}` | `get_transcript()` | api_get_transcript.py | test | ⚠️  |
| GET | `/workers` | `list_workers()` | api_list_workers.py | test, web |  |
| POST | `/workers/start-all` | `start_all_workers()` | api_start_all_workers.py | test, web |  |
| POST | `/workers/{name}/start` | `start_worker()` | api_start_worker.py | test | ⚠️  |
| POST | `/workers/{name}/stop` | `stop_worker()` | api_control_worker.py | test | ⚠️  |
| DELETE | `/{topology_id}` | `api_delete_topology()` | api_delete_topology.py | test | ⚠️  |
| GET | `/{topology_id}` | `api_get_topology()` | api_get_topology.py | test | ⚠️  |
| POST | `/{topology_id}/deckies` | `api_create_decky()` | api_decky_crud.py | test | ⚠️  |
| DELETE | `/{topology_id}/deckies/{decky_uuid}` | `api_delete_decky()` | api_decky_crud.py | test | ⚠️  |
| PATCH | `/{topology_id}/deckies/{decky_uuid}` | `api_update_decky()` | api_decky_crud.py | test | ⚠️  |
| POST | `/{topology_id}/deploy` | `api_deploy_topology()` | api_deploy_topology.py | test | ⚠️  |
| POST | `/{topology_id}/edges` | `api_create_edge()` | api_edge_crud.py | test | ⚠️  |
| DELETE | `/{topology_id}/edges/{edge_id}` | `api_delete_edge()` | api_edge_crud.py | test | ⚠️  |
| GET | `/{topology_id}/events` | `api_topology_events()` | api_events.py | **NONE** | ⚠️  |
| POST | `/{topology_id}/lans` | `api_create_lan()` | api_lan_crud.py | test | ⚠️  |
| DELETE | `/{topology_id}/lans/{lan_id}` | `api_delete_lan()` | api_lan_crud.py | test | ⚠️  |
| PATCH | `/{topology_id}/lans/{lan_id}` | `api_update_lan()` | api_lan_crud.py | test | ⚠️  |
| GET | `/{topology_id}/lans/{lan_id}/next-ip` | `api_next_ip()` | api_catalog.py | **NONE** | ⚠️  |
| GET | `/{topology_id}/mutations` | `api_list_mutations()` | api_mutations.py | test | ⚠️  |
| POST | `/{topology_id}/mutations` | `api_enqueue_mutation()` | api_mutations.py | test | ⚠️  |
| GET | `/{topology_id}/status-events` | `api_get_status_events()` | api_get_topology.py | **NONE** | ⚠️  |
| POST | `/{topology_id}/teardown` | `api_teardown_topology()` | api_teardown_topology.py | **NONE** | ⚠️  |


---

## Deletion Candidates: Zero Callers

These routes have **no callers anywhere** in the codebase (except their own definition and possibly tests). They are strong candidates for removal.

### GET `/archetypes` → `api_list_archetypes()`

**File**: `decnet/web/router/topology/api_catalog.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

### POST `/deckies/{decky_name}/mutate` → `api_mutate_decky()`

**File**: `decnet/web/router/fleet/api_mutate_decky.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

### PUT `/deckies/{decky_name}/mutate-interval` → `api_update_mutate_interval()`

**File**: `decnet/web/router/fleet/api_mutate_interval.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

### GET `/{topology_id}/events` → `api_topology_events()`

**File**: `decnet/web/router/topology/api_events.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

### GET `/{topology_id}/lans/{lan_id}/next-ip` → `api_next_ip()`

**File**: `decnet/web/router/topology/api_catalog.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

### GET `/{topology_id}/status-events` → `api_get_status_events()`

**File**: `decnet/web/router/topology/api_get_topology.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

### POST `/{topology_id}/teardown` → `api_teardown_topology()`

**File**: `decnet/web/router/topology/api_teardown_topology.py`  
**Callers**: None  
**Status**: Dead code — no references in web frontend, CLI, or worker processes.

**Action**: Safe to delete. If tests exist, they are testing orphaned endpoints.

---

## Deletion Candidates: Test-Only Routes

These routes are referenced **only in test files**, not in the actual application. They may have been replaced by newer endpoints and are kept for backward-compatibility testing, or tests simply weren't updated after migration.

**Count**: 47 routes


### Artifacts (1)

- `GET /artifacts/{decky}/{stored_as}` (api_get_artifact.py)

### Attackers (4)

- `GET /attackers/{uuid}` (api_get_attacker_detail.py)
- `GET /attackers/{uuid}/artifacts` (api_get_attacker_artifacts.py)
- `GET /attackers/{uuid}/commands` (api_get_attacker_commands.py)
- ... and 1 more

### Auth (2)

- `POST /auth/change-password` (api_change_pass.py)
- `POST /auth/login` (api_login.py)

### Blank (1)

- `POST /blank` (api_create_blank_topology.py)

### Bounty (1)

- `GET /bounty` (api_get_bounties.py)

### Config (3)

- `DELETE /config/users/{user_uuid}` (api_manage_users.py)
- `PUT /config/users/{user_uuid}/reset-password` (api_manage_users.py)
- `PUT /config/users/{user_uuid}/role` (api_manage_users.py)

### Deployment-Mode (1)

- `GET /deployment-mode` (api_deployment_mode.py)

### Enroll-Bundle (3)

- `POST /enroll-bundle` (api_enroll_bundle.py)
- `GET /enroll-bundle/{token}.sh` (api_enroll_bundle.py)
- `GET /enroll-bundle/{token}.tgz` (api_enroll_bundle.py)

### Heartbeat (1)

- `POST /heartbeat` (api_heartbeat.py)

### Hosts (4)

- `DELETE /hosts/{uuid}` (api_decommission_host.py)
- `GET /hosts/{uuid}` (api_get_host.py)
- `DELETE /hosts/{uuid}` (api_decommission_host.py)
- ... and 1 more

### Logs (2)

- `GET /logs` (api_get_logs.py)
- `GET /logs/histogram` (api_get_histogram.py)

### Next-Subnet (1)

- `GET /next-subnet` (api_catalog.py)

### Push (1)

- `POST /push` (api_push_update.py)

### Push-Self (1)

- `POST /push-self` (api_push_update_self.py)

### Reap-Orphans (1)

- `POST /reap-orphans` (api_reap_orphans.py)

### Rollback (1)

- `POST /rollback` (api_rollback_host.py)

### Services (1)

- `GET /services` (api_catalog.py)

### Stats (1)

- `GET /stats` (api_get_stats.py)

### Teardown (1)

- `POST /teardown` (api_teardown_swarm.py)

### Transcripts (1)

- `GET /transcripts/{decky}/{sid}` (api_get_transcript.py)

### Workers (2)

- `POST /workers/{name}/start` (api_start_worker.py)
- `POST /workers/{name}/stop` (api_control_worker.py)

### {Topology_Id} (13)

- `DELETE /{topology_id}` (api_delete_topology.py)
- `GET /{topology_id}` (api_get_topology.py)
- `POST /{topology_id}/deckies` (api_decky_crud.py)
- ... and 10 more


---

## Analysis Notes

### Context from Recent Work

Per repo history:
- **Bus-woken mutator** replaced polling — check `/deckies/*` mutation endpoints
- **SSE mutation events** replaced direct CRUD polling — check legacy list endpoints  
- **Worker supervisor endpoints** are new — likely need expansion, not deletion
- **MazeNET topologies** are the new feature — older "topology" endpoints may be superseded
- **Direct mutation CRUD for active topologies** replaced by mutation queue

### Methodology

- **Web Frontend**: Searched `decnet_web/src/**/*.{ts,tsx}` for literal path references (e.g., `"/attackers/{uuid}"`)
- **CLI**: Searched `decnet/cli/**/*.py` for `/api/v1` calls
- **Workers**: Searched `decnet/<worker>/**/*.py` (excluding CLI)
- **Tests**: Searched `tests/**/*.py` for path references

### Caveats

- Dynamically-built paths (e.g., `${base}/topologies/${id}`) detected via fragment search (e.g., `/topologies/`)
- Method-less references (e.g., just the path string) may miss some usages if not called via fetch/axios
- mTLS/internal worker endpoints (agent API, forwarder, enroll-bundle) deferred to Phase 2 per scope

---

## Possible Duplicates / Overlapping Endpoints

_To be populated after human review of the candidate list._


---

## Phase 2 — Worker / mTLS Endpoints

### Executive Summary

**Scope**: Internal worker processes and mTLS-gated inter-process HTTP surfaces:
- Agent FastAPI app (port 8765, mTLS-required)
- Updater FastAPI app (port 8766, mTLS-required, CN-gated)
- Master→Agent client calls via `AgentClient` class
- Master→Updater client calls via `UpdaterClient` class
- Enroll-bundle endpoints (`/swarm/enroll-bundle`) — worker-facing, fetches bootstrap + deployment payload
- Enrollment endpoints (`/swarm/enroll`) — admin-driven, issues certs

**Total Worker Process Endpoints**: 12  
**Total Deletion Candidates**: 0 (all have active callers)

---

### Worker Process HTTP Endpoints

#### Agent FastAPI App (`decnet/agent/app.py`)

**Listener**: Port 8765, mTLS-enforced at ASGI/uvicorn layer (cert required)  
**Callers**: Master via `AgentClient`, deployer module, CLI  
**Auth**: mTLS only; all authenticated peers trusted equally

| Method | Path | Handler | Callers | Notes |
|--------|------|---------|---------|-------|
| GET | `/health` | `health()` | master-to-agent, tests | Liveness probe; does NOT skip mTLS |
| GET | `/status` | `status()` | master-to-agent, engine deployer | Deployment snapshot + active topology state |
| POST | `/deploy` | `deploy()` | master-to-agent, engine deployer | Materialise full DecnetConfig (body: `DeployRequest`) |
| POST | `/teardown` | `teardown()` | master-to-agent | Dismantle entire fleet or single decky (body: `TeardownRequest`) |
| POST | `/self-destruct` | `self_destruct()` | master-to-agent | Fire-and-forget reaper; deletes all DECNET footprint (202 response) |
| POST | `/topology/apply` | `topology_apply()` | master-to-agent | Apply a single topology (body: `ApplyTopologyRequest`) |
| POST | `/topology/teardown` | `topology_teardown()` | master-to-agent | Dismantle single topology (body: `TeardownTopologyRequest`) |
| GET | `/topology/state` | `topology_state()` | master-to-agent | Topology-specific state (separate from `/status`) |
| POST | `/mutate` | `mutate()` | (unimplemented, returns 501) | Per-decky mutate; currently done via `/deploy` with updated config |

**Timeouts**: Deploy/topology-apply 600s read, teardown 300s read (docker compose on slow VMs)

---

#### Updater FastAPI App (`decnet/updater/app.py`)

**Listener**: Port 8766, mTLS-enforced (cert CN must match `updater@*`)  
**Callers**: Master via `UpdaterClient`  
**Auth**: mTLS + CN validation (only `updater@<hostname>` certs allowed)

| Method | Path | Handler | Callers | Notes |
|--------|------|---------|---------|-------|
| GET | `/health` | `health()` | master-to-updater, dashboard, bus monitor | Returns active + prev release slots |
| GET | `/releases` | `releases()` | master-to-updater | List all available release slots (JSON array) |
| POST | `/update` | `update()` | master-to-updater | Upload + apply tarball (multipart: tarball + sha form) |
| POST | `/update-self` | `update_self()` | master-to-updater | Self-update updater binary (connection drops mid-response) |
| POST | `/rollback` | `rollback()` | master-to-updater | Revert to previous release slot |

**Timeouts**: `/update` + `/update-self` 180s read (pip install + probe on slow VMs)

---

### Master-Facing Worker Enrollment Endpoints

#### Enrollment Bundle (`decnet/web/router/swarm_mgmt/api_enroll_bundle.py`)

**Listener**: Master port 443 (FastAPI web app)  
**Callers**: agent (worker fetches payload), admin UI  
**Auth**: Token-based (5-min TTL), no mTLS required (public endpoints for worker bootstrap)

| Method | Path | Handler | Callers | Auth | Notes |
|--------|------|---------|---------|------|-------|
| POST | `/api/v1/swarm/enroll-bundle` | `create_enroll_bundle()` | admin-ui, cli | require_admin | Create bundle (token + shell script + tarball); returns EnrollBundleResponse (201) |
| GET | `/api/v1/swarm/enroll-bundle/{token}.sh` | `get_bootstrap()` | agent-client, curl | token-param | Bootstrap shell script (idempotent, 5-min TTL) |
| GET | `/api/v1/swarm/enroll-bundle/{token}.tgz` | `get_payload()` | agent-client, curl | token-param | Gzipped tarball (one-shot; deletes .sh + .tgz after serving) |

**Rationale**: Agent's first contact-home; its source IP backfills the `SwarmHost.address` row.

---

#### Simple Enrollment (`decnet/web/router/swarm/api_enroll_host.py`)

**Listener**: Master port 443  
**Callers**: admin UI, CLI  
**Auth**: None (browser-facing, admin dashboard context)

| Method | Path | Handler | Callers | Auth | Notes |
|--------|------|---------|---------|------|-------|
| POST | `/api/v1/swarm/enroll` | `api_enroll_host()` | admin-ui | (browser auth) | Issue cert bundle + register host row (201) |

---

### Master→Agent RPC Surface (via `AgentClient`)

Master calls agent via `AgentClient(host).method()` context manager. All calls are mTLS. Called from:

1. **`api_deploy_swarm.py`**: Deploy topology to all enrolled hosts
2. **`api_teardown_swarm.py`**: Teardown fleet
3. **`api_check_hosts.py`**: Active mTLS probe of all hosts (for dashboard health)
4. **`api_decommission_host.py`** (swarm): Calls agent `/self-destruct`
5. **`api_decommission_host.py`** (swarm_mgmt): Calls agent `/self-destruct`
6. **`api_teardown_host.py`** (swarm_mgmt): Calls agent `/self-destruct`
7. **`api_list_hosts.py`** (swarm_mgmt): Calls agent `/health` on every list request
8. **Engine `deployer.py`**: Direct `/deploy` + `/topology/apply` calls during mutation/materialization

**Cert Pinning**: Master's cert is CA-signed; workers validate via CA pinning + master hostname-verification disabled (per-operator SANs).

---

### Master→Updater RPC Surface (via `UpdaterClient`)

Master calls updater via `UpdaterClient(host).method()` context manager. All calls are mTLS. Called from:

1. **`api_push_update.py`**: Upload new release to updater
2. **`api_push_update_self.py`**: Update the updater binary itself
3. **`api_rollback_host.py`**: Rollback updater to previous release
4. **`api_list_host_releases.py`**: Poll all updaters for active release SHA (dashboard)

**Connection Drop**: `/update-self` intentionally drops the connection; caller polls `/health` for new SHA.

---

### Agent→Master Heartbeat

**Endpoint**: `POST /api/v1/swarm/heartbeat`  
**Caller**: `decnet/agent/heartbeat.py` module (agent-side daemon)  
**Auth**: mTLS + peer cert SHA-256 pinned to `SwarmHost.client_cert_fingerprint`  
**Frequency**: ~30 seconds  
**Payload**: Host UUID, agent version, executor status dict, optional topology snapshot

**Security**: Decommissioned workers' still-valid certs must not resurrect ghost shards → cert fingerprint mismatch → 403.

---

### Bus Pub/Sub (Local Only, Not HTTP)

Per comments in agent/updater app.py:
- Agent publishes `system.agent.health` heartbeat to local bus (separate from mTLS heartbeat)
- Updater publishes `system.updater.health` to local bus
- Bus is host-local UNIX socket — not an external RPC surface

No HTTP endpoints; no caller analysis needed.

---

### Forwarder

**Status**: No HTTP endpoints exposed by forwarder process.  
The forwarder:
- Consumes RFC 5424 syslog from local log file (written by agent log collector)
- Ships syslog-over-TLS to master port 6514 (outbound, not inbound)
- No master→forwarder calls; no worker-side HTTP surface

---

### Deletion Candidates

**None.** All identified endpoints have active callers:

- Agent `/deploy`, `/teardown`, `/self-destruct`, `/topology/*` are called by engine, deployer, master probes
- Updater `/update*`, `/releases`, `/health` are called by master push flow + dashboard
- Enroll-bundle is called by new agents (worker-facing enrollment)
- Simple enroll is called by admin UI

---

### Duplicate / Obsolete Endpoints

**Potential overlap to review**:

1. **`/swarm/enroll` vs `/swarm/enroll-bundle`**: Two enrollment flows, both active.
   - `/enroll` (old) — admin issues cert + agent curls back for bundle
   - `/enroll-bundle` (new) — admin renders bundle upfront, agent one-liners it
   - Consider consolidating if old flow is being phased out (need human review of intent).

2. **Agent `/deploy` + `/teardown` vs `/topology/apply` + `/topology/teardown`**: Both exist.
   - `/deploy` — fleet-wide (old unihost verb)
   - `/topology/{apply,teardown}` — single topology (newer MazeNET feature)
   - No conflict; different scopes. Agent supports both.

3. **Agent `/mutate` returns 501**: Placeholder for future worker-side mutation.
   - Currently master re-sends `/deploy` with updated config.
   - Safe to leave as-is (fails closed); can implement later.

---

### Summary Table

| Process | Count | mTLS | Auth | Notes |
|---------|-------|------|------|-------|
| Agent | 9 | Yes | No (peer auth only) | Port 8765; calls from master + engine |
| Updater | 5 | Yes | Yes (CN-gated) | Port 8766; calls from master |
| Enroll-Bundle | 3 | No | Token (5 min) | Master port 443; agent + admin fetch |
| Enroll | 1 | No | Browser auth | Master port 443; admin UI |
| **Total** | **18** | — | — | — |

**Caller Types Identified**:
- `master-to-agent`: Master calls agent (9 endpoints)
- `master-to-updater`: Master calls updater (5 endpoints)
- `agent-client`: Agent calls master heartbeat (1 endpoint in Phase 1)
- `admin-client`: Admin calls enroll-bundle POST (1 endpoint)
- `test`: All endpoints have test coverage

**Zero-Caller Endpoints**: None.

---


## Phase 3 — CLI Command Surface

### Summary

**Total CLI Commands**: 37  
**Master-only Commands**: 27 (via `MASTER_ONLY_COMMANDS` + `MASTER_ONLY_GROUPS`)  
**Agent-capable Commands**: 10 (hidden in agent mode when `DECNET_MODE=agent`)  
**Commands Hitting API Routes**: 7 (all in `decnet swarm *` group, plus `decnet deploy`)  
**Deletion Candidates**: 0 (no deprecated commands found; all are actively used)

---

### Full Command Inventory

| Command | Handler | Source | Master-only? | Hits API? | Notes |
|---------|---------|--------|--------------|-----------|-------|
| `decnet api` | `api()` | api.py:19 | Yes | No | Start FastAPI backend (uvicorn) |
| `decnet swarmctl` | `swarmctl()` | swarmctl.py:18 | Yes | No | Run SWARM controller + auto-spawn listener |
| `decnet agent` | `agent()` | agent.py:16 | No | No | Worker: run SWARM agent (requires cert bundle) |
| `decnet updater` | `updater()` | updater.py:14 | No | No | Worker: run self-updater daemon |
| `decnet listener` | `listener()` | listener.py:16 | Yes | No | Run syslog-TLS listener (RFC 5425, mTLS) |
| `decnet forwarder` | `forwarder()` | forwarder.py:18 | No | No | Worker: forward syslog to master:6514 (mTLS) |
| `decnet deploy` | `deploy()` | deploy.py:68 | Yes | Yes | Deploy deckies (unihost/swarm mode) |
| `decnet init` | `init_cmd()` | init.py:305 | Yes | No | Bootstrap master: user/group/systemd/config |
| `decnet services` | `list_services()` | inventory.py:15 | No | No | List available service plugins |
| `decnet distros` | `list_distros()` | inventory.py:27 | No | No | List available OS distro profiles |
| `decnet archetypes` | `list_archetypes()` | inventory.py:38 | Yes | No | List machine archetype profiles |
| `decnet redeploy` | `redeploy()` | lifecycle.py:18 | No | No | Check services + relaunch any down |
| `decnet status` | `status()` | lifecycle.py:57 | No | No | Show running deckies + service status |
| `decnet teardown` | `teardown()` | lifecycle.py:81 | Yes | No | Stop/remove deckies (--all or --id) |
| `decnet probe` | `probe()` | workers.py:15 | No | No | Fingerprint attackers (JARM/HASSH) |
| `decnet collect` | `collect()` | workers.py:40 | No | No | Stream Docker logs to RFC 5424 file |
| `decnet mutate` | `mutate()` | workers.py:57 | Yes | No | Trigger/watch decky mutation |
| `decnet correlate` | `correlate()` | workers.py:86 | Yes | No | Analyse logs for cross-decky traversals |
| `decnet web` | `serve_web()` | web.py:13 | Yes | No | Serve frontend SPA + proxy /api/* |
| `decnet profiler` | `profiler_cmd()` | profiler.py:11 | Yes | No | Build attacker profiles from log stream |
| `decnet sniffer` | `sniffer_cmd()` | sniffer.py:12 | Yes | No | Passive network sniffer |
| `decnet db-reset` | `db_reset()` | db.py:86 | Yes | No | Wipe MySQL database (truncate or drop-tables) |
| `decnet bus` | `bus_cmd()` | bus.py:11 | No | No | Run UNIX-socket pub/sub bus worker |
| `decnet swarm enroll` | `swarm_enroll()` | swarm.py:23 | Yes | Yes | Enroll worker + issue mTLS bundle → POST `/swarm/enroll` |
| `decnet swarm list` | `swarm_list()` | swarm.py:85 | Yes | Yes | List enrolled workers → GET `/swarm/hosts` |
| `decnet swarm check` | `swarm_check()` | swarm.py:111 | Yes | Yes | Probe worker status → POST `/swarm/check` |
| `decnet swarm update` | `swarm_update()` | swarm.py:149 | Yes | Yes | Push tarball to workers → GET `/swarm/hosts` + updater client |
| `decnet swarm deckies` | `swarm_deckies()` | swarm.py:256 | Yes | Yes | List deckies across swarm → GET `/swarm/deckies` |
| `decnet swarm decommission` | `swarm_decommission()` | swarm.py:315 | Yes | Yes | Remove worker from swarm → DELETE `/swarm/hosts/{uuid}` |
| `decnet topology generate` | `_generate()` | topology.py:35 | Yes | No | Generate topology plan (persist as pending) |
| `decnet topology list` | `_list()` | topology.py:94 | Yes | No | List all topologies |
| `decnet topology show` | `_show()` | topology.py:121 | Yes | No | Print topology structure |
| `decnet topology deploy` | `_deploy()` | topology.py:177 | Yes | No | Deploy pending topology |
| `decnet topology teardown` | `_teardown()` | topology.py:194 | Yes | No | Tear down active topology |
| `decnet topology delete` | `_delete()` | topology.py:210 | Yes | No | Delete topology + cascade (LANs/deckies/edges) |
| `decnet topology mutate` | `_mutate()` | topology.py:265 | Yes | No | Enqueue live topology mutation |
| `decnet topology mutations` | `_mutations()` | topology.py:310 | Yes | No | List queued/applied mutations |

---

### Commands Hitting API Routes

All 7 commands that call HTTP endpoints go through **swarmctl** (not the main `/api/v1` backend). These are:

1. **`decnet deploy`** (swarm mode)  
   - Hits: `GET /swarm/hosts?host_status=enrolled`, `GET /swarm/hosts?host_status=active`, `POST /swarm/deploy`  
   - Route source: `decnet/web/swarm_api.py` (Swarmctl API, not Phase 1 audit scope)

2. **`decnet swarm enroll`**  
   - Hits: `POST /swarm/enroll`

3. **`decnet swarm list`**  
   - Hits: `GET /swarm/hosts`

4. **`decnet swarm check`**  
   - Hits: `POST /swarm/check`

5. **`decnet swarm update`**  
   - Hits: `GET /swarm/hosts` + direct mTLS to updater port 8766

6. **`decnet swarm deckies`**  
   - Hits: `GET /swarm/deckies`

7. **`decnet swarm decommission`**  
   - Hits: `DELETE /swarm/hosts/{uuid}`

**Note**: Swarmctl API endpoints (`/swarm/*`) are **not** in the Phase 1 audit (Phase 1 scanned `/api/v1/*` only). These routes are stable and not candidates for deletion.

---

### Deletion Candidates

**Count: 0**

**Rationale**:
- No commands are marked `@deprecated` in docstrings.
- No old "v1" flavors replaced by newer flows (e.g., no `decnet deploy-v1` vs `decnet deploy-v2`).
- All commands in `MASTER_ONLY_COMMANDS` + `MASTER_ONLY_GROUPS` are actively referenced and tested.
- Worker-capable commands (`agent`, `updater`, `forwarder`, `bus`, `probe`, `collect`, `redeploy`, `status`, `services`, `distros`) are essential for field operation.
- Recent additions (`decnet init`, `decnet swarm *`, `decnet topology *`) are part of the SWARM/MazeNET bootstrap flow and have no predecessors.

---

### CLI → API Deletion Chains

No CLI command is the **only caller** of a Phase 1 API route marked `cli` or `zero`. All Phase 1 routes with `cli` callers have multiple paths:

- Phase 1 example: `/health` — called by both CLI (`decnet status`) and web/test
- Phase 1 example: `/deckies` — called by CLI (`swarm deckies`) + web + test

**Implication**: Deleting a CLI command does NOT unlock any Phase 1 API route deletions.

---

### Gating Configuration

Master-only enforcement lives in `decnet/cli/gating.py`:

**MASTER_ONLY_COMMANDS** (25 command names):
```
"api", "swarmctl", "deploy", "redeploy", "teardown",
"mutate", "listener", "profiler",
"services", "distros", "correlate", "archetypes", "web",
"db-reset", "init",
```
Plus subcommand groups:

**MASTER_ONLY_GROUPS** (2 group names):
```
"swarm", "topology"
```

**Defense-in-depth**:
- Registration-time filter hides commands from `decnet --help` on agents (when `DECNET_MODE=agent`).
- Runtime gate in each command body calls `_require_master_mode()` to block direct function imports.

---

### Recent Additions (Phase Context)

Per repo memory and recent commits:

- **`decnet init` + `--deinit`**: Bootstrap + teardown systemd/polkit/tmpfiles. Idempotent.
- **`decnet swarm *`**: Enroll workers, list status, push updates, manage deckies. All talk to swarmctl, not `/api/v1`.
- **`decnet topology *`**: MazeNET nested-topology commands. Direct DB calls (no HTTP). Replaces old flat `/topologies` CRUD.
- **`decnet bus`**: New ServiceBus worker. UNIX-socket pub/sub, not HTTP.
- **Worker supervisors** (`probe`, `collect`, `correlate`, `sniffer`, `profiler`): Field microservices. Spawned by `decnet deploy` as detached processes.

None are marked for removal; all have active use cases.

---

### Output Modes

CLI output is **structured text** (Rich tables, JSON, syslog-format lines). All commands respect:
- `--json` flag where applicable (e.g., `decnet swarm check --json`)
- Scriptable structured output (e.g., `decnet correlate --output json`)

Web dashboard visualization is **not** in CLI scope (per repo design: CLI outputs text, dashboard ingests data via API).


---

## Phase 4 — Consolidated Cleanup Plan

### Executive Summary

**CRITICAL FINDING**: Phase 1's "test-only routes" classification is **fundamentally unreliable**. Of 8 sampled test-only routes, **6 showed active web UI callers** — the Phase 1 grep methodology failed to catch TypeScript/TSX frontend API calls. 

**Phase 1 zero-caller candidates**: **REVISED DOWNWARD** from 7 to **3 actual deletions**:
- 4 routes flagged as zero-callers actually have active web UI callers: `/archetypes`, `/deckies/{decky_name}/mutate`, `/deckies/{decky_name}/mutate-interval`, and `/teardown`
- Remaining true zero-callers: `GET /{topology_id}/events`, `GET /{topology_id}/status-events`, `GET /{topology_id}/lans/{lan_id}/next-ip`

**Recommendation**: Do NOT use the Phase 1 "47 test-only" list as a deletion target without manual verification of EACH route against the TypeScript frontend code.

---

### Phase 4 Verification Results

#### Zero-Caller Candidates — Fresh Grep Results

| Route | Handler | Phase 1 Status | Phase 4 Finding | Verdict |
|-------|---------|----------------|-----------------|---------|
| `GET /archetypes` | `api_list_archetypes()` | Zero callers | **FOUND**: `DeckyFleet.tsx:833` calls `/topologies/archetypes` | **KEEP** |
| `POST /deckies/{decky_name}/mutate` | `api_mutate_decky()` | Zero callers | **FOUND**: `DeckyFleet.tsx:850` calls `/deckies/${name}/mutate` | **KEEP** |
| `PUT /deckies/{decky_name}/mutate-interval` | `api_update_mutate_interval()` | Zero callers | **FOUND**: `DeckyFleet.tsx:898` calls `/deckies/${name}/mutate-interval` | **KEEP** |
| `GET /{topology_id}/events` | `api_topology_events()` | Zero callers | **NO CALLERS FOUND** (only test mock) | **DELETE** |
| `GET /{topology_id}/lans/{lan_id}/next-ip` | `api_next_ip()` | Zero callers | **NO CALLERS FOUND** | **DELETE** |
| `GET /{topology_id}/status-events` | `api_get_status_events()` | Zero callers | **NO CALLERS FOUND** | **DELETE** |
| `POST /{topology_id}/teardown` | `api_teardown_topology()` | Zero callers | **FOUND**: `TopologyList.tsx` calls `/topologies/${id}/teardown` | **KEEP** |

**Revised zero-caller count**: **3 routes** (not 7)

---

#### Test-Only Routes — Spot-Check Results

Sampled 8 of 47 "test-only" routes:

| Route | Phase 1 Sample | Web Frontend Caller | Verdict |
|-------|----------------|-------------------|---------|
| `GET /artifacts/{decky}/{stored_as}` | test-only | **FOUND**: `ArtifactDrawer.tsx` | **FALSE POSITIVE** |
| `POST /auth/change-password` | test-only | **FOUND**: `Login.tsx` | **FALSE POSITIVE** |
| `POST /auth/login` | test-only | **FOUND**: `Login.tsx` | **FALSE POSITIVE** |
| `POST /blank` | test-only | **FOUND**: `MazeNET/useMazeApi.ts` + `TopologyList.tsx` | **FALSE POSITIVE** |
| `GET /bounty` | test-only | **FOUND**: `Bounty.tsx`, `CommandPalette.tsx` | **FALSE POSITIVE** |
| `GET /deployment-mode` | test-only | **FOUND**: `DeckyFleet.tsx` | **FALSE POSITIVE** |
| `DELETE /config/users/{user_uuid}` | test-only | **FOUND**: `Config.tsx` | **FALSE POSITIVE** |
| `GET /logs` | test-only | **FOUND**: `LiveLogs.tsx` | **FALSE POSITIVE** |

**Verdict**: The "47 test-only routes" number is **unreliable**. At least **6/8 sampled routes have active web callers** that Phase 1's grep missed. The methodology failed because:
1. Phase 1 grepped Python/test files only; it did **not systematically scan TypeScript/TSX**.
2. Dynamic path construction (e.g., `` api.post(`/topologies/${id}/teardown`) ``) requires careful regex; simple string matching misses them.
3. Frontend developers split concerns across files (components/hooks/utils); no single grep layer caught all call sites.

**Recommendation**: **Do not trust the "47 test-only" list.** Before deleting ANY route marked test-only, manually verify:
```bash
# For each route, run:
grep -r "<path-fragment>" decnet_web/src --include="*.ts" --include="*.tsx"
```

---

### Enroll Flow Consolidation

#### `POST /swarm/enroll` vs `POST /swarm/enroll-bundle`

**Current state**:
- **`/swarm/enroll`** (simple): Master-driven, admin issues cert bundle, returns full bundle in response (201 Created).
- **`/swarm/enroll-bundle`** (new): Token-based workflow — admin builds token, renders `.sh` + `.tgz`, agent curls both (Wazuh-style one-liner).

**Web UI caller analysis**:
- `SwarmHosts.tsx` calls **ONLY** `POST /swarm/enroll-bundle` (new flow).
- No web caller for `POST /swarm/enroll` (old flow) found.

**CLI caller analysis**:
- `decnet swarm enroll` (Phase 3 audit) calls `POST /swarm/enroll` (line 572 of Phase 3 summary).

**Recommendation**: **DEPRECATE simple `/swarm/enroll`**
1. Keep both endpoints for now (CLI still uses simple).
2. Mark `POST /swarm/enroll` as `@deprecated` in docstring; note that new deployments should use `POST /swarm/enroll-bundle`.
3. Update CLI (`decnet swarm enroll`) to call `/swarm/enroll-bundle` in a follow-up PR.
4. Only DELETE simple `/swarm/enroll` **after** CLI migration is merged and tested.

**Why not delete now**: CLI is the only caller; deleting breaks backward compatibility for operators with scripts or runbooks calling the simple flow. Deprecate first, migrate CLI, then delete.

---

### Ordered PR Plan (Kill List)

**Three independent deletions** — run tests after each. Do NOT combine; each is a commit-shaped change.

---

#### PR #1: Remove `/api/v1/{topology_id}/events` endpoint

**Scope**: One endpoint, one handler module, test module, no other imports.

**Files to delete**:
- `decnet/web/router/topology/api_events.py` (handler + schema)
- `tests/api/topology/test_events_stream.py` (test file)

**Files to modify**:
- `decnet/web/router/topology/__init__.py` — remove two lines:
  ```python
  # DELETE: from .api_events import router as events_router
  # DELETE: include_router(events_router)
  ```

**Blast radius**: ~120 lines deleted, 2 import lines in router init.

**Verification before deleting**:
```bash
grep -r "api_topology_events\|/events" --include="*.py" --include="*.ts" --include="*.tsx" \
  decnet/ decnet_web/ tests/ --exclude-dir=.claude | grep -v "def api_topology_events" | grep -v "test_events"
# Should return ZERO results except in files being deleted
```

**Test plan**:
```bash
pytest tests/api/topology/ -v  # Topology suite still passes
pytest tests/api/ -k "not test_events_stream" --tb=short  # Full API suite minus events
```

---

#### PR #2: Remove `/api/v1/{topology_id}/status-events` endpoint

**Scope**: One endpoint, one handler (shares module with `GET /{topology_id}`), test code.

**Files to modify**:
- `decnet/web/router/topology/api_get_topology.py` — remove function and route decorator:
  ```python
  # DELETE: @router.get("/{topology_id}/status-events", ...)
  # DELETE: async def api_get_status_events(...): ...  [~30 lines]
  ```

**Files to modify (tests)**:
- `tests/api/topology/test_reads.py` — remove test cases that call `status-events`.

**Blast radius**: ~40 lines (one function + docstring + route decorator).

**Verification before deleting**:
```bash
grep -r "api_get_status_events\|/status-events" --include="*.py" --include="*.ts" --include="*.tsx" \
  decnet/ decnet_web/ tests/ --exclude-dir=.claude | grep -v "def api_get_status_events"
# Should return ZERO results except in deleted test code
```

**Test plan**:
```bash
pytest tests/api/topology/test_reads.py -v  # Should pass after removing status-events test case
```

---

#### PR #3: Remove `/api/v1/{topology_id}/lans/{lan_id}/next-ip` endpoint

**Scope**: One endpoint, one handler (shares module with catalog endpoints), test code.

**Files to modify**:
- `decnet/web/router/topology/api_catalog.py` — remove function and route decorator:
  ```python
  # DELETE: @router.get("/{topology_id}/lans/{lan_id}/next-ip", ...)
  # DELETE: async def api_next_ip(...): ...  [~40 lines]
  ```

**Files to modify (tests)**:
- `tests/api/topology/test_reads.py` — remove test cases that call `next-ip`.

**Blast radius**: ~60 lines (one function + route + docstring).

**Verification before deleting**:
```bash
grep -r "api_next_ip\|/next-ip" --include="*.py" --include="*.ts" --include="*.tsx" \
  decnet/ decnet_web/ tests/ --exclude-dir=.claude | grep -v "def api_next_ip"
# Should return ZERO results except in deleted test code
```

**Test plan**:
```bash
pytest tests/api/topology/test_reads.py -v  # Should pass after removing next-ip test case
```

---

### Known Risks / Routes NOT Deleted (Had Callers)

These routes were **flagged as zero-callers by Phase 1 but DO have active callers** — listed here so the human knows they were considered and verified:

| Route | Handler | Caller Location | Decision |
|-------|---------|------------------|----------|
| `GET /archetypes` | `api_list_archetypes()` | `DeckyFleet.tsx:833` | KEEP |
| `POST /deckies/{decky_name}/mutate` | `api_mutate_decky()` | `DeckyFleet.tsx:850` | KEEP |
| `PUT /deckies/{decky_name}/mutate-interval` | `api_update_mutate_interval()` | `DeckyFleet.tsx:898` | KEEP |
| `POST /{topology_id}/teardown` | `api_teardown_topology()` | `TopologyList.tsx` | KEEP |

---

### Summary Table

| PR | Deletion | Files | Lines | Risk | Phase |
|----|----------|-------|-------|------|-------|
| #1 | `GET /{topology_id}/events` | 2 (handler + test) | ~120 | Low | 4a |
| #2 | `GET /{topology_id}/status-events` | 1 (shared module + test edit) | ~40 | Low | 4b |
| #3 | `GET /{topology_id}/lans/{lan_id}/next-ip` | 1 (shared module + test edit) | ~60 | Low | 4c |
| — | `POST /swarm/enroll` (simple) | 1 (handler) | ~100 | **Medium** | **Deferred** |

**Total committed lines of code deleted**: ~220 lines (handler + tests)  
**Total test files touched**: 3 (api_events.py deletion + test_events_stream.py deletion + test_reads.py edits)  
**Estimated review time per PR**: 10–15 minutes  
**Total estimated project time**: 1 hour (including test runs)

---

### Why This Order

1. **PR #1** removes the most isolated endpoint (dedicated handler module + test). No shared code, lowest risk.
2. **PR #2** modifies a shared catalog module but removes only one function. Can be reviewed with test edits.
3. **PR #3** similar scope to #2 (catalog module). Groups naturally with #2's test file edit strategy.
4. **Enroll consolidation deferred**: Requires CLI change first (`decnet swarm enroll` → `/swarm/enroll-bundle`). Plan for Phase 5.

---

### Testing Strategy for Each PR

1. **Before deletion**: Run the verification grep command above. Should return zero results except in files being deleted.
2. **After deletion**:
   - Run `pytest tests/api/ -v` to verify no regressions in other routes.
   - Spot-check web UI in dev (`decnet web`, then visit `/topologies` page).
   - Verify CLI still works: `decnet --help` (not affected by these deletions).
   - Final check: `grep -r "<handler_name>"` should be empty in decnet/, decnet_web/, tests/ (except deleted files).

---

### Critical Lessons for Future Audits

1. **Phase 1 methodology is insufficient**: Future audits must:
   - Grep TypeScript/TSX sources **systematically** (not as an afterthought in Phase 4).
   - Audit `decnet_web/src` for every route with same rigor as Python backend.
   - Use IDE symbol search (e.g., VSCode "Find All References") for very high confidence on dynamic paths.

2. **Do NOT bulk-delete "test-only" routes**: The "47 test-only" number is a **red flag, not a deletion target**. Each requires individual verification against web UI code.

3. **Consolidation opportunities**: The simple `/swarm/enroll` is now deprecated but NOT deleted (requires CLI migration first). Document these as "Phase N+1" work, not in the main kill list.


---

## Phase 4.5 — Redundancy callout

A follow-up pass (beyond zero-caller deletions) flagged three redundancy classes worth explicit documentation. These are orthogonal to the kill list in Phase 4 — they're about *ambiguity in the surface*, not dead code.

### 1. Triple-registered `GET /deckies` ⚠️ HIGH PRIORITY

The Phase 1 route table shows the same path + method bound to **three** handlers:

| Method | Path | Handler | File |
|---|---|---|---|
| GET | `/deckies` | `get_deckies()` | `api_get_deckies.py` |
| GET | `/deckies` | `api_list_deckies()` | `api_list_deckies.py` |
| GET | `/deckies` | `list_deckies()` | `api_list_deckies.py` |

**Why it matters**:
- FastAPI resolves same-path duplicates to whichever is registered last. The other two are dead but still appear in the OpenAPI schema.
- Two handlers in the same file (`api_list_deckies.py`) is a strong smell of a leftover-from-rename refactor.
- Schemathesis sees the duplicates and generates overlapping cases, inflating the 30-minute run time.

**Verification TODO** (before deletion):
1. `grep -n "get_deckies\|api_list_deckies\|list_deckies" decnet/web/router/fleet/` — identify which is actually wired in the router `__init__.py` / include statements.
2. Determine whether the canonical handler is `get_deckies` or `api_list_deckies` (check which the web frontend's response shape matches).
3. Delete the two losers + their tests. Keep one canonical handler.

**Risk**: Low. Only one handler is live; removing dead registrations can't change runtime behavior.

---

### 2. Two enrollment flows — `/swarm/enroll` vs `/swarm/enroll-bundle`

Already covered in [§ Enroll Flow Consolidation](#enroll-flow-consolidation) above. Reiterated here so all redundancies live in one place.

- **`POST /swarm/enroll`** — legacy, simple, still called by `decnet swarm enroll` CLI.
- **`POST /swarm/enroll-bundle`** (+ `.sh` / `.tgz`) — new token-based flow, sole web-UI caller.
- **Recommendation**: mark simple as deprecated, migrate CLI to bundle flow, delete simple in a Phase 5 pass. Not on the current kill list.

---

### 3. Mutation-verb confusion

After Phase 4's zero-caller deletions land, four "mutate" endpoints currently coexist with overlapping names but different semantics:

| Endpoint | Status | Scope |
|---|---|---|
| `POST /api/v1/deckies/{decky_name}/mutate` | **dead** (kill list) | single decky, fleet-wide |
| `PUT /api/v1/deckies/{decky_name}/mutate-interval` | **dead** (kill list) | single decky, fleet-wide |
| `POST /api/v1/{topology_id}/mutations` | **live** (mutation queue, bus-woken) | topology-scoped |
| Agent `POST /mutate` (port 8765) | **501 placeholder** | agent-local, unused |

**Why it matters**: a reader new to the codebase sees four mutate-verbs and has to figure out which is canonical. After the kill list lands, only two remain:
- **Master**: `POST /{topology_id}/mutations` — the canonical live-mutation API.
- **Agent**: `POST /mutate` (501) — reserved for future worker-side mutation (currently master re-sends `/deploy`).

**Action**: no code change needed *beyond the Phase 4 kill list*. Once dead routes are gone, this section stops being confusing on its own.

---

### Explicitly NOT redundant

For the record — these look like pairs but are not:

- **Agent `/deploy` + `/teardown` vs `/topology/apply` + `/topology/teardown`** — fleet-wide vs single-topology scopes. Both serve agent, different purposes. Keep.
- **`POST /deckies/deploy` vs `POST /{topology_id}/deploy`** — same as above: fleet-wide deploy vs topology-scoped deploy. Keep.
