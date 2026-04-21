# DECNET — Technical Debt Register

> Last updated: 2026-04-21 — DEBT-032 opened (fingerprint rotation detection).
> Severity: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low

---

## 🔴 Critical

### ~~DEBT-001 — Hardcoded JWT fallback secret~~ ✅ RESOLVED
~~**File:** `decnet/env.py:15`~~  
Fixed in commit `b6b046c`. `DECNET_JWT_SECRET` is now required; startup raises `ValueError` if unset or set to a known-bad value.

### ~~DEBT-002 — Default admin credentials in code~~ ✅ CLOSED (by design)
`DECNET_ADMIN_PASSWORD` defaults to `"admin"` intentionally — the web dashboard enforces a password change on first login (`must_change_password=1`). Startup enforcement removed as it broke tooling without adding meaningful security.

### ~~DEBT-003 — Hardcoded LDAP password placeholder~~ ✅ CLOSED (false positive)
`templates/ldap/server.py:73` — `"<sasl_or_unknown>"` is a log label for SASL auth attempts, not an operational credential. The LDAP template is a honeypot; it has no bind password of its own.

### ~~DEBT-004 — Wildcard CORS with no origin restriction~~ ✅ RESOLVED
~~**File:** `decnet/web/api.py:48-54`~~  
Fixed in commit `b6b046c`. `allow_origins` now uses `DECNET_CORS_ORIGINS` (env var, defaults to `http://localhost:8080`). `allow_methods` and `allow_headers` tightened to explicit allowlists.

---

## 🟠 High

### ~~DEBT-005 — Auth module has zero test coverage~~ ✅ RESOLVED
~~**File:** `decnet/web/auth.py`~~  
Comprehensive test suite added in `tests/api/` covering login, password change, token validation, and JWT edge cases.

### ~~DEBT-006 — Database layer has zero test coverage~~ ✅ RESOLVED
~~**File:** `decnet/web/sqlite_repository.py`~~  
`tests/api/test_repository.py` added — covers log insertion, bounty CRUD, histogram queries, stats summary, and fuzz testing of all query paths. In-memory SQLite with `StaticPool` ensures full isolation.

### ~~DEBT-007 — Web API routes mostly untested~~ ✅ RESOLVED
~~**Files:** `decnet/web/router/` (all sub-modules)~~  
Full coverage added across `tests/api/` — fleet, logs, bounty, stream, auth all have dedicated test modules with both functional and fuzz test cases.

### ~~DEBT-008 — Auth token accepted via query string~~ ✅ RESOLVED
~~**File:** `decnet/web/dependencies.py:33-34`~~  
Query-string token fallback removed. `get_current_user` now accepts only `Authorization: Bearer <token>` header. Tokens no longer appear in access logs or browser history.

### ~~DEBT-009 — Inconsistent and unstructured logging across templates~~ ✅ CLOSED (false positive)
All service templates already import from `decnet_logging` and use `syslog_line()` for structured output. The `print(line, flush=True)` present in some templates is the intentional Docker stdout channel for container log forwarding — not unstructured debug output.

### ~~DEBT-010 — `decnet_logging.py` duplicated across all 19 service templates~~ ✅ RESOLVED
~~**Files:** `templates/*/decnet_logging.py`~~  
All 22 per-directory copies deleted. Canonical source lives at `templates/decnet_logging.py`. `deployer.py` now calls `_sync_logging_helper()` before `docker compose up` — it copies the canonical file into each active template build context automatically.

---

## 🟡 Medium

### DEBT-011 — No database migration system
**File:** `decnet/web/db/sqlite/repository.py`  
Schema is created during startup via `SQLModel.metadata.create_all`. There is no Alembic or equivalent migration layer. Schema changes across deployments require manual intervention or silently break existing databases.  
**Status:** Architectural. Deferred — requires Alembic integration and migration history bootstrapping.

### ~~DEBT-012 — No environment variable validation schema~~ ✅ RESOLVED
~~**File:** `decnet/env.py`~~  
`DECNET_API_PORT` and `DECNET_WEB_PORT` now validated via `_port()` — enforces integer type and 1–65535 range, raises `ValueError` with a clear message on bad input.

### ~~DEBT-013 — Unvalidated input on `decky_name` route parameter~~ ✅ RESOLVED
~~**File:** `decnet/web/router/fleet/api_mutate_decky.py:10`~~  
`decky_name` now declared as `Path(..., pattern=r"^[a-z0-9\-]{1,64}$")` — FastAPI rejects non-matching values with 422 before any downstream processing.

### ~~DEBT-014 — Streaming endpoint has no error handling~~ ✅ RESOLVED
~~**File:** `decnet/web/router/stream/api_stream_events.py`~~  
`event_generator()` now wrapped in `try/except`. `asyncio.CancelledError` is handled silently (clean disconnect). All other exceptions log server-side via `log.exception()` and yield an `event: error` SSE frame to the client.

### ~~DEBT-015 — Broad exception detail leaked to API clients~~ ✅ RESOLVED
~~**File:** `decnet/web/router/fleet/api_deploy_deckies.py:78`~~  
Raw exception message no longer returned to client. Full exception now logged server-side via `log.exception()`. Client receives generic `"Deployment failed. Check server logs for details."`.

### ~~DEBT-016 — Unvalidated log query parameters~~ ✅ RESOLVED
~~**File:** `decnet/web/router/logs/api_get_logs.py:12-19`~~  
`search` capped at `max_length=512`. `start_time` and `end_time` validated against `^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$` regex pattern. FastAPI rejects invalid input with 422.

### ~~DEBT-017 — Silent DB lock retry during startup~~ ✅ RESOLVED
~~**File:** `decnet/web/api.py:20-26`~~  
Each retry attempt now emits `log.warning("DB init attempt %d/5 failed: %s", attempt, exc)`. After all retries exhausted, `log.error()` is emitted so degraded startup is always visible in logs.

### ~~DEBT-018 — No Docker HEALTHCHECK in any template~~ ✅ RESOLVED
~~**Files:** All 20 `templates/*/Dockerfile`~~  
All 24 Dockerfiles updated with:  
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1
```

### ~~DEBT-019 — Most template containers run as root~~ ✅ RESOLVED
~~**Files:** All `templates/*/Dockerfile` except Cowrie~~  
All 24 Dockerfiles now create a `decnet` system user, use `setcap cap_net_bind_service+eip` on the Python binary (allows binding ports < 1024 without root), and drop to `USER decnet` before `ENTRYPOINT`.

### ~~DEBT-020 — Swagger/OpenAPI disabled in production~~ ✅ RESOLVED
~~**File:** `decnet/web/api.py:43-45`~~  
All route decorators now declare `responses={401: {"description": "Not authenticated"}, 422: {"description": "Validation error"}}`. OpenAPI schema is complete for all endpoints.

### ~~DEBT-021 — `sqlite_repository.py` is a god module~~ ✅ RESOLVED
~~**File:** `decnet/web/sqlite_repository.py` (~400 lines)~~  
Fully refactored to `decnet/web/db/` modular layout: `models.py` (SQLModel schema), `repository.py` (abstract base), `sqlite/repository.py` (SQLite implementation), `sqlite/database.py` (engine/session factory). Commit `de84cc6`.

### DEBT-026 — IMAP/POP3 bait emails not configurable via service config
**Files:** `templates/imap/server.py`, `templates/pop3/server.py`, `decnet/services/imap.py`, `decnet/services/pop3.py`  
Bait emails are hardcoded. A stub env var `IMAP_EMAIL_SEED` is read but currently ignored. Full implementation requires:
1. `IMAP_EMAIL_SEED` points to a JSON file with a list of `{from_, to, subject, date, body}` dicts.
2. `templates/imap/server.py` loads and merges/replaces `_BAIT_EMAILS` from that file at startup.
3. `decnet/services/imap.py` `compose_fragment()` reads `service_cfg["email_seed"]` and injects `IMAP_EMAIL_SEED` + a bind-mount for the seed file into the compose fragment.
4. Same pattern for POP3 (`POP3_EMAIL_SEED`).  
**Status:** Stub in place — full wiring deferred to next session.

---

### DEBT-027 — Dynamic Bait Store
**Files:** `templates/redis/server.py`, `templates/ftp/server.py`
The bait store and honeypot files are hardcoded. A dynamic injection framework should be created to populate this payload across different honeypots.
**Status:** Deferred — out of current scope.

### DEBT-028 — Test coverage for `api_deploy_deckies.py`
**File:** `decnet/web/router/fleet/api_deploy_deckies.py` (24% coverage)
The deploy endpoint exercises Docker Compose orchestration via `decnet.engine.deploy`, which creates MACVLAN/IPvlan networks and runs `docker compose up`. Meaningful tests require mocking the entire Docker SDK + subprocess layer, coupling tightly to implementation details.
**Status:** Deferred — test after Docker-in-Docker CI is available.

### DEBT-029 — Service-wide pub/sub bus worker (`decnet bus`) ✅ RESOLVED
**Files:** `decnet/bus/` (`worker.py`, `factory.py`, `unix_client.py`, `unix_server.py`, `protocol.py`, `fake.py`, `base.py`, `topics.py`), `decnet/cli/bus.py`, `deploy/decnet-bus.service`, `tests/bus/` (62 tests green).

`CLAUDE.md` promises a `ServiceBus` worker and a `get_bus()` factory, but neither exists. Today there is no event plumbing between workers: mutator, correlator, profiler, sniffer, and prober cannot publish state transitions to interested consumers. The web SSE endpoint (`/stream`) polls the DB every ~1s inside its generator loop as a result. Downstream features that need this infrastructure: live topology mutations (DEBT-030), pulsating/live topology visualization, automatic mutations, network traffic simulation, attacker-pool push updates.

MVP scope (**host-local**):
1. `decnet bus` long-running worker, systemd-supervised like every other worker. Runs on every host — master and each swarm agent — independently.
2. Transport: **UNIX-domain socket** (default `/run/decnet/bus.sock`, fallback `~/.decnet/bus.sock` in dev). Kernel-authenticated peer delivery; authorization is socket file permissions (0660, group=`decnet`). No TCP, no mTLS, no external broker.
3. Wire protocol: tiny hand-rolled framing — 1 ASCII verb line (`PUB <topic>`, `SUB <pattern>`, `EVT <topic>`, `HELLO`, `BYE`) + 4-byte big-endian body length + orjson body. Shared `matches(pattern, topic)` helper implements NATS-style wildcards (`*` = one token, `>` = one-or-more trailing tokens).
4. Factory `get_bus()` returns a client with `publish(topic, payload)` / `subscribe(pattern) -> Subscription` (async ctx + async iterator). In-process `FakeBus` for unit tests; `NullBus` when `DECNET_BUS_ENABLED=false`.
5. Topic hierarchy locked early: `topology.{id}.mutation.{state}`, `topology.{id}.status`, `decky.{id}.state`, `decky.{id}.traffic`, `attacker.observed`, `system.log`, `system.bus.health`.
6. Delivery semantics: **at-most-once, fire-and-forget**. Per-subscriber bounded queue with drop-oldest on overflow. No replay, no persistence, no queue groups, no ordering guarantees. DB remains the source of truth; the bus is the notification layer only.
7. First consumer proving end-to-end: SSE route for topology events (DEBT-030).
8. Later: migrate `/stream` off its internal poll loop onto the bus for global events.

**Cross-host federation is out of MVP scope.** Each host runs its own bus — swarm agents and the master do not share a bus substrate. If a use case emerges that requires cross-host pub/sub, it will land as a `decnet bus --bridge-tcp` mode that proxies the UNIX socket over the existing swarm mTLS infra. DEBT-030 is master-only and therefore unblocked by this deferral.

**Status:** ✅ Resolved — MVP shipped. Host-local UNIX-socket bus, `get_bus()` factory, `decnet bus` worker with heartbeats, systemd unit, 62 unit/integration tests green. DEBT-030 is now unblocked.

### DEBT-030 — Live (hot) topology mutations via web UI ✅ RESOLVED (Phase A)
**Files:** `decnet/web/router/topology/api_mutations.py` (enqueue endpoint already exists), `decnet/mutator/engine.py` + `ops.py` (reconciler already applies all 7 ops), `web/src/hooks/useMazeApi.ts` (missing enqueue methods), `web/src/components/MazeNET.tsx` (editor treats every topology as pending).

**Backend is already there:**
- `TopologyMutation` table (`decnet/web/db/models.py:322-358`) supports `add_lan`, `remove_lan`, `attach_decky`, `detach_decky`, `remove_decky`, `update_decky`, `update_lan`.
- `POST /topologies/{id}/mutations` enqueues, gated to `active|degraded`.
- Mutator watch loop (`decnet/mutator/engine.py:136-190`) claims atomically, dispatches to `ops.py`, does Docker best-effort, flips topology to `degraded` on failure.

**Gap is entirely in the frontend + event delivery:**
1. `useMazeApi.ts` has no `enqueueMutation()` peer to `deployTopology()`; editor edits on `active` topologies currently no-op / 4xx.
2. No mutation-status UI (pending / applying / applied / failed badges, audit log).
3. No server→client push channel for mutation state transitions — depends on DEBT-029.

**Design (agreed):**
- **Staged buffer** (client-side, Zustand, not persisted): every editor action pushes a `TopologyMutation` onto `pendingOps[]`. Undo = pop. Reset = clear.
- **Apply (N changes)** button opens a diff modal rendering ops in plain English, then POSTs the batch. Batch carries the `topology.version` observed when staging began; server returns 409 on drift.
- **Batch atomicity = honest partial.** Server enqueues N rows in order; mutator applies one-by-one. If op 3 fails, 1-2 stay applied, topology flips to `degraded`, user decides to fix-forward or enqueue a manual revert. (Docker ops aren't transactional; pretending otherwise causes worse bugs than honesty.)
- **Visual states compose** per existing rule: `pending-mutation`, `applying`, `failed` layer on top of `running / inactive / selected`, never replace them.
- **Push via SSE over the bus** (not polling): new route `GET /api/v1/topologies/{id}/events` subscribes to `topology.{id}.*` on the service bus and forwards as SSE. Envelope: `{v, type, ts, payload}`. Day-one event types: `mutation.enqueued|applying|applied|failed`, `topology.status_changed`, `topology.version_bumped`. Room to grow: `decky.state_changed`, `decky.traffic`, `attacker.observed`.
- **Separate from `/stream`** deliberately: different auth scopes, different fan-out shape (per-topology vs global), different failure isolation. Two routes, one bus.

**Status:** ✅ Resolved (Phase A) — end-to-end bus→UI plumbing shipped.
- Mutator publishes every state transition on the bus (`mutation.applying|applied|failed`, `status`); fire-and-forget, DB remains source of truth.
- Mutator watch loop is bus-woken via `topology.*.mutation.enqueued`; 10s poll stays as fallback heartbeat so a dropped wake event costs latency, not correctness.
- New route `GET /api/v1/topologies/{id}/events` streams per-topology SSE — snapshot on connect + live forwarding of bus events, 15s keepalive, `?token=` query-param auth matching `/stream`.
- Web editor opens the SSE when topology is `active|degraded`, refetches on `mutation.applied|failed|status`, surfaces a `LIVE` / `CONNECTING…` header indicator.
- Smoke: `scripts/bus/smoke-mutator.sh` verifies the full mutator-family topic hierarchy round-trips through a live bus worker.

**Phase B follow-up (deferred):** staged-buffer editor (Apply (N changes) + optimistic visual states using `NodeBase.status='mutating'`). Today's Phase A refetches the whole topology on each applied event — correct but not yet optimistic. The hooks + API method + SSE consumer that Phase B needs are already in place (`useTopologyStream.ts`, `useMazeApi.enqueueMutation`).

### ~~DEBT-031 — Service workers don't use the bus~~ ✅ RESOLVED
**Files:** `decnet/collector/`, `decnet/correlation/`, `decnet/profiler/`, `decnet/sniffer/`, `decnet/prober/`, `decnet/ingester/`, `decnet/agent/`, `decnet/forwarder/`, `decnet/updater/`.

DEBT-029 shipped the bus; DEBT-030 proved the pattern end-to-end through the mutator and the web editor. Every other worker still ignores the bus entirely — they neither publish the state transitions their consumers would want nor subscribe to events that could replace polling / cut latency. The plumbing is ready; the workers aren't wired in.

**Guiding principle: bus is optional.** Workers must not take a hard dependency on the bus. If `get_bus()` fails or `DECNET_BUS_ENABLED=false`, the worker logs one warning at startup and continues in pre-bus mode (poll loops, DB-only state). This mirrors `decnet/mutator/engine.py:run_watch_loop` — try to connect, catch broadly, log, degrade to poll-only. Copy that pattern; don't invent a new one.

**Publish (per worker, what should land on the bus):**
- `collector` — `system.log` batches / high-severity lines as they ingest (fan-out to dashboards / live views).
- `correlator` — `attacker.observed` on first sighting, `attacker.session.{started|ended}` on session boundaries.
- `profiler` — `attacker.scored` when a profile score crosses a threshold.
- `sniffer` — `decky.{id}.traffic` summaries (bounded rate; drop-oldest is fine per bus semantics).
- `prober` — `decky.{id}.state` transitions when a realism probe flips health.
- `ingester` — `system.log` for structured forwarder-originated batches.
- `agent` / `forwarder` / `updater` — `system.{worker}.health` heartbeats + lifecycle events (start, stop, self-update applied).

**Subscribe (per worker, what they could react to instead of polling):**
- `correlator` / `profiler` — wake on `system.log` instead of polling the logs table; poll stays as fallback.
- `prober` — wake on `decky.*.state` to re-probe immediately after a mutation-applied event.
- Any worker that currently polls the DB on a fixed interval — add a bus-wake `asyncio.Event` exactly like the mutator's.

**Constraints (non-negotiable):**
1. DB stays the source of truth. A dropped bus event costs latency, never correctness — every subscriber must still have a poll fallback.
2. Publishes are fire-and-forget, wrapped in `try/except log.warning`. A bus publish failure must never break the worker's primary loop.
3. No new topics outside the hierarchy documented in `CLAUDE.md` / `wiki-checkout/Service-Bus.md`. Extend `decnet/bus/topics.py` with helpers + constants; don't hand-roll topic strings at the callsite.
4. Test with `FakeBus` (see `tests/bus/conftest.py::fake_bus`). Every new publish path gets a unit test asserting the event lands on a fake subscriber; every new wake path gets a test asserting the worker re-enters its loop faster than the poll interval.
5. `DECNET_BUS_ENABLED=false` must leave every worker functional — add a CI matrix row or at minimum an explicit test per worker proving it.

**Suggested rollout order** (ship one worker at a time, one commit each): sniffer → prober → correlator → profiler → collector → ingester → agent/forwarder/updater. Sniffer and prober are the highest-value publishers for the live-topology visualization story; correlator/profiler unlock the attacker-pool push updates that MazeNET's observed-entities view currently polls for.

**Status:** Resolved. Nine-commit rollout landed on `dev`:

1. Prep — extracted `publish_safely` + `make_thread_safe_publisher` to `decnet/bus/publish.py`; added `attacker.*`, `system.<worker>.health` topic builders.
2. Sniffer — `decky.{id}.traffic` per flow-summary / fingerprint event (bounded by the bus's drop-oldest queue).
3. Prober — `attacker.fingerprinted` with probe family (jarm/hassh/tcpfp) in `event.type`.
4. Correlator — `attacker.observed` on first sighting, hooked via an optional `publish_fn` on `CorrelationEngine`; the profiler worker carries the bus.
5. Profiler — `attacker.scored` per DB-committed profile upsert.
6. Collector — `system.log` per ingested parsed event (compact payload: decky/service/event_type/attacker_ip/timestamp).
7. Ingester — `system.log` per DB-committed batch (`event.type = "batch_committed"`, payload includes offset).
8. Agent / Forwarder / Updater — shared `run_health_heartbeat` helper emits `system.<worker>.health` every 30s.

**Deferred (out of DEBT-031 scope, tracked for follow-ups):**
- **Realism-probe `decky.{id}.state`** — the prober as it exists today fingerprints attackers, not deckies. Publishing `decky.{id}.state` on realism-flip needs a separate realism probe path we don't have yet.
- **Correlator `session.started` / `session.ended`** — `CorrelationEngine` is a batch class with no session state. A session-boundary signal would need session tracking introduced first; constants are reserved in `decnet/bus/topics.py`.
- **Standalone `decnet correlate` worker** — the rollout plan presumed one; today the engine runs inside the profiler worker, which is the right shape for the current data flow.
- **Bus-wake subscriptions** — publishes landed; subscribe-side (e.g. prober re-probe on `decky.*.state`) was not wired to avoid coupling the wake pattern to a subscriber we don't yet have.

### DEBT-032 — Prober can't detect fingerprint rotation without mutation
**Files:** `decnet/prober/worker.py` (~lines 235, 286, 334, 392), `decnet/web/db/models.py` (new `decky_service_fingerprints` table).

Substrate identity is `(service_name, implementation_fingerprint)`, not service name alone. A base-image rebuild that rotates OpenSSH 8.4 → 9.2 — or any recompose that changes JARM / HASSH / TCP fingerprint without changing the service list — is a substrate transition from the attacker's recon POV, and today the correlation graph sees none of it.

The prober already computes JARM (`worker.py:286`), HASSH (`worker.py:334`), and TCP fingerprint (`worker.py:392`), and emits each as RFC 5424 syslog + optional bus publish. What's missing is **per-(decky, service, probe_type) persistence** to diff against: the current dedup set `probed: dict[IP → {probe_type → set(ports)}]` (`worker.py:235`) is in-memory and scoped to one run, so any restart loses history and any same-IP probe on a changed substrate can't be detected as a change.

**Design:**
1. New SQLModel table `decky_service_fingerprints` keyed by `(decky_name, service, probe_type)` with `last_hash, last_seen_at, sample_count`. One upsert per probe; bounded by fleet × probe families.
2. Prober reads `last_hash` before emitting; on diff, emits a new `substrate_fingerprint_changed` event (RFC 5424 syslog + `decky.{id}.fingerprint` bus topic) with `{decky, service, probe_type, old_hash, new_hash}`. On match, upsert the timestamp and skip the event.
3. Correlator consumes the new event kind into a parallel per-decky index (mirroring the mutation index landed in this session) and interleaves `🔍 decky-03 hassh drift` markers in `AttackerTraversal.fingerprints_during`.
4. Divergence detector: compare `substrate_state(t)` fold (mutations) vs `observed_identity(t)` fold (fingerprints) per decky. A fingerprint change without a preceding mutation ⇒ `substrate_divergence` finding — container drift, compromised base image, rootkit banner rewrite, or prober lag. Falls out of the data model for free once both streams exist.

**Prerequisite satisfied:** mutation event stream + correlator mutation-kind parser landed alongside this DEBT entry (commits `f875350`, `fa0cdb3`, `bf5ed7a`, `d4d8a2a` on `dev`). The fingerprint stream plugs into the same substrate: same RFC 5424 emission pattern, sibling per-decky engine index, same timeline interleaving.

**Status:** Open — deferred to its own commit sequence. The dedup state in `worker.py:235` is the only thing standing between "JARM hash computed" and "substrate rotation detected."

---

## 🟢 Low

### ~~DEBT-022 — Debug `print()` in correlation engine~~ ✅ CLOSED (false positive)
`decnet/correlation/engine.py:20` — The `print()` call is inside the module docstring as a usage example, not in executable code. No production code path affected.

### DEBT-023 — Unpinned base Docker images
**Files:** All `templates/*/Dockerfile`  
`debian:bookworm-slim` and similar tags are used without digest pinning. Image contents can silently change on `docker pull`, breaking reproducibility and supply-chain integrity.  
**Status:** Deferred — requires `docker pull` access to resolve current digests for each base image.

### ~~DEBT-024 — Stale service version hardcoded in Redis template~~ ✅ RESOLVED
~~**File:** `templates/redis/server.py:15`~~  
`REDIS_VERSION` updated from `"7.0.12"` to `"7.2.7"` (current stable).

### ~~DEBT-025 — No lock file for Python dependencies~~ ✅ RESOLVED
~~**Files:** Project root~~  
`requirements.lock` generated via `pip freeze`. Reproducible installs now available via `pip install -r requirements.lock`.

---

## Summary

| ID | Severity | Area | Status |
|----|----------|------|--------|
| ~~DEBT-001~~ | ✅ | Security / Auth | resolved `b6b046c` |
| ~~DEBT-002~~ | ✅ | Security / Auth | closed (by design) |
| ~~DEBT-003~~ | ✅ | Security / Infra | closed (false positive) |
| ~~DEBT-004~~ | ✅ | Security / API | resolved `b6b046c` |
| ~~DEBT-005~~ | ✅ | Testing | resolved |
| ~~DEBT-006~~ | ✅ | Testing | resolved |
| ~~DEBT-007~~ | ✅ | Testing | resolved |
| ~~DEBT-008~~ | ✅ | Security / Auth | resolved |
| ~~DEBT-009~~ | ✅ | Observability | closed (false positive) |
| ~~DEBT-010~~ | ✅ | Code Duplication | resolved |
| DEBT-011 | 🟡 Medium | DB / Migrations | deferred (Alembic scope) |
| ~~DEBT-012~~ | ✅ | Config | resolved |
| ~~DEBT-013~~ | ✅ | Security / Input | resolved |
| ~~DEBT-014~~ | ✅ | Reliability | resolved |
| ~~DEBT-015~~ | ✅ | Security / API | resolved |
| ~~DEBT-016~~ | ✅ | Security / API | resolved |
| ~~DEBT-017~~ | ✅ | Reliability | resolved |
| ~~DEBT-018~~ | ✅ | Infra | resolved |
| ~~DEBT-019~~ | ✅ | Security / Infra | resolved |
| ~~DEBT-020~~ | ✅ | Docs | resolved |
| ~~DEBT-021~~ | ✅ | Architecture | resolved `de84cc6` |
| ~~DEBT-022~~ | ✅ | Code Quality | closed (false positive) |
| DEBT-023 | 🟢 Low | Infra | deferred (needs docker pull) |
| ~~DEBT-024~~ | ✅ | Infra | resolved |
| ~~DEBT-025~~ | ✅ | Build | resolved |
| DEBT-026 | 🟡 Medium | Features | deferred (out of scope) |
| DEBT-027 | 🟡 Medium | Features | deferred (out of scope) |
| DEBT-028 | 🟡 Medium | Testing | deferred (needs DinD CI) |
| DEBT-029 | 🟡 Medium | Architecture / Bus | ✅ resolved |
| DEBT-030 | 🟡 Medium | Web / Live mutations | ✅ resolved (Phase A) |
| ~~DEBT-031~~ | ✅ | Workers / Bus integration | resolved |
| DEBT-032 | 🟡 Medium | Correlation / Prober | open |

**Remaining open:** DEBT-011 (Alembic), DEBT-023 (image pinning), DEBT-026 (modular mailboxes), DEBT-027 (Dynamic bait store), DEBT-028 (deploy endpoint tests), DEBT-032 (fingerprint rotation detection).
**Estimated remaining effort:** ~16 hours. DEBT-030 Phase B (optimistic staged-buffer editor) is a follow-up, not debt.
