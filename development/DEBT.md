# DECNET — Technical Debt Register

> Last updated: 2026-04-25 — Cred coverage rolled out across 9 more services (HTTP family + DB hash creds + form bodies + MongoDB SCRAM); RDP/SMB/NLA capture deferred to DEBT-040.
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

### DEBT-033 — Transcript day-shard rotation
**Files:** `decnet/templates/_shared/sessrec/sessrec.c`, `decnet/web/router/transcripts/`.

Session recording v1 (SSH/Telnet interactive-session capture) stores asciinema events in **one JSONL shard per (decky, UTC day)**: `sessions-YYYY-MM-DD.jsonl`. This bounds inode count (O(days) not O(sessions)) and blunts the obvious "`while true; do login; exit; done`" DoS, but a determined attacker can still keep a single day's shard growing until the 200 MB disk-free precheck trips. When that happens the recorder silently skips new recordings (`session_skipped reason=disk_pressure`) until midnight or until operator cleanup — which is *safe*, but it also means an attacker can blind the recorder for the rest of the day by filling disk once.

Proper fix is size-based rotation on the day shard:
1. Recorder (or a sidecar job) rotates `sessions-YYYY-MM-DD.jsonl` → `sessions-YYYY-MM-DD.1.jsonl` when size crosses e.g. 500 MB; keep last N rotations (default 4 → hard ceiling ≈ 2 GB/day/decky).
2. Oldest rotations drop on write pressure (FIFO), not on read.
3. API router shard-index cache (see `transcripts/` router, built from session-recording plan) gains an mtime-keyed scan across all rotations for the requested day when resolving a `sid`, not just the live shard. Cache invalidation already keys on `(path, st_mtime_ns)` so rotation drops stale entries automatically.
4. Same trigger (disk pressure or a new config knob `DECNET_TRANSCRIPT_DAY_MAX_MB`) decides when to fire; no background timer needed if the recorder itself checks size before each append.

**Why deferred from v1:** the per-session 10 MB cap + disk-free precheck together give bounded worst-case behavior ("recorder quietly stops; disk stays healthy") that is acceptable for a first release. Rotation is a correctness-under-load improvement, not a correctness baseline, and it couples recorder write-path + API read-path changes that are cleaner to land as one commit after v1 ships.

**Status:** Open — implement after v1 session recording lands and we have real-world session sizes to calibrate the rotation threshold.

### ✅ DEBT-034 — Worker supervisor (START buttons in Config → Workers)
> **Shipped 2026-04-22.** systemd units for the five missing workers
> (`collector` / `profiler` / `sniffer` / `prober` / `mutator`) +
> `decnet.target`, polkit rule scoping `manage-units` to `decnet-*.service`
> for the `decnet` group, `systemd_control` helper, single-worker +
> `start-all` endpoints, `installed` flag on `WorkerStatus`, and UI
> wiring. Deferred items (SWARM-host start/stop via mTLS API;
> DECNET-side crash-quarantine policy) remain as named follow-ups.

**Files:** `packaging/systemd/*.service` + `decnet.target` (**new**), `packaging/polkit/50-decnet-workers.rules` (**new**), `decnet/web/services/systemd_control.py` (**new**), `decnet/web/router/workers/api_start_worker.py` + `api_start_all_workers.py` (**new**), `decnet_web/src/components/Config.tsx` (enable START buttons).

The Workers panel (Config → Workers) landed with bus-based STOP but every START button is a disabled placeholder. STOP works because a running worker can subscribe to its own `system.<name>.control` topic and SIGTERM-self-signal when it sees `{"action": "stop"}`. START has the inverse problem — a *stopped* worker has no subscriber, so the same bus pattern cannot bring it back up. Something outside the worker must own the process lifecycle.

**Decision: lean on systemd.** DECNET workers are already systemd-supervised in production (`deploy/decnet-bus.service` shipped with DEBT-029; the rest follow the same pattern). Building a DECNET-native supervisor (`decnetd`) would duplicate `Restart=on-failure`, crash backoff, log routing into journald, and boot ordering — all of which systemd already does correctly. The only non-systemd host we care about is the dev box, where operators can start workers by hand.

**v1 scope:**
1. **Unit files** for every worker in `packaging/systemd/`: `decnet-bus`, `decnet-api`, `decnet-collector`, `decnet-profiler`, `decnet-sniffer`, `decnet-prober`, `decnet-mutator`. Each declares `Restart=on-failure`, `RestartSec=5s`, `User=decnet`, `Group=decnet`. A `decnet.target` groups them for `systemctl start decnet.target`. Bus is startable too — chicken-and-egg is fine: systemd brings it up, the API's cached `get_app_bus()` result won't self-heal without an API restart, but that's the existing singleton limitation (documented in `decnet/bus/app.py`), not a supervisor problem.
2. **Polkit rule** (`packaging/polkit/50-decnet-workers.rules`) allowing the `decnet` group to `start` / `stop` / `restart` units matching `decnet-*.service` and `decnet.target` without a password. The API runs as `decnet`, so `systemctl --no-ask-password start decnet-<name>` just works.
3. **`decnet/web/services/systemd_control.py`** — small helper wrapping `systemctl start|stop|status <unit>` via `asyncio.create_subprocess_exec`. Hardcoded unit name mapping from `KNOWN_WORKERS` (prevents command injection; name validation already enforced at the router). Exposes `start(name)`, `stop(name)`, `is_active(name)`, `list_installed()` returning `set[str]`.
4. **New admin endpoints:**
   - `POST /api/v1/workers/{name}/start` — validates against `KNOWN_WORKERS`, shells out via the helper, returns 202 on success with `{"accepted": true, "worker": <name>, "action": "start"}`. 503 if systemd is unreachable (e.g. dev box without systemd).
   - `POST /api/v1/workers/start-all` — **best-effort**. Iterates `KNOWN_WORKERS`, calls `start()` on each, aggregates results. Returns `{"started": [...], "failed": [{name, reason}], "already_running": [...]}` with 200 even on partial success. UI surfaces a summary toast.
   - Keep existing bus-based STOP endpoint — it already works without root; no need to route STOP through systemd.
5. **UI (`Config.tsx`):**
   - Detect unit availability once per panel mount via `GET /api/v1/workers` enriched with `installed: bool` per row (added to `WorkerStatus`). START button enabled only when `installed == true`.
   - Existing "START ALL WORKERS" placeholder in the header wires to `POST /workers/start-all`; toast renders `"STARTED · 5 · ALREADY RUNNING · 2 · FAILED · 1 (bus: permission denied)"`.
   - Add a `starting` row state (spinner) between intent and observed heartbeat; transitions to `ok` on next refresh, `unknown`/`stale` if the unit never comes up (systemd log link in tooltip).
6. **Tests:**
   - `tests/web/services/test_systemd_control.py` — monkeypatch `asyncio.create_subprocess_exec`, assert the right argv.
   - `tests/api/workers/test_start_workers.py` — 202 admin / 403 viewer / 404 unknown name for single-worker start; aggregation shape for start-all with a mix of success/failure.
   - Frontend test coverage stays out of scope (no harness in repo).

**Deferred (documented on this ticket, not separate DEBTs):**

- **a. SWARM-host worker start/stop.** Today `agent` / `forwarder` / `updater` publish heartbeats to their *own* host's bus, not the master's — the Workers panel rows stay `unknown` by design. A master-originated start/stop for those daemons needs to ride the existing swarm mTLS API (`/api/v1/swarm/hosts/{id}/workers/{name}/{action}`), not the bus. Out of v2 as well — not a near-term need. When we ship it, reuse the same systemd helper on the agent side behind the mTLS boundary.

- **b. DECNET-side crash-quarantine policy.** v1 uses systemd's defaults (`Restart=on-failure`, `RestartSec=5s`, no upper bound on restart count) because they're battle-tested and cover 95% of operational reality. A sophisticated circuit-breaker — "quarantine worker X after N crashes in M minutes, expose the quarantine state in the panel" — is valuable for a honeypot-in-production context where a compromised template could cause tight crash loops that mask themselves as flapping. Design sketch: extend the worker_registry to track `(name, last_crash_ts)` triples sourced from `systemctl is-failed`, flip a row to `quarantined` state after threshold, require an admin "CLEAR QUARANTINE" click (→ `systemctl reset-failed`) before further auto-restart. Not blocking v1.

**Status:** Open. Depends on the Workers panel (shipped) and `deploy/decnet-bus.service` pattern being extended to the other workers.

### DEBT-036 — Session-profile ingester (keystroke-dynamics extraction from transcript shards)
**Files:** `decnet/web/ingester.py` (or new sibling under `decnet/session_profiler/`), `decnet/web/db/models/attackers.py:SessionProfile` (table already exists, ships empty), `decnet/templates/_shared/sessrec/sessrec.c` (emitter side — already done), `decnet/web/router/attackers/api_get_attacker_detail.py` (consumer — already joins SessionProfile when present).

The `SessionProfile` SQLModel table has been committed to storage since session recording v1 landed (see `decnet/web/db/models/attackers.py:97-143`). Every column — `kd_iki_mean`, `kd_iki_stdev`, `kd_iki_p50`, `kd_iki_p95`, `kd_enter_latency_p50/p95`, `kd_burst_ratio`, `kd_think_ratio`, `kd_ctrl_backspace/wkill/ukill/abort/eof`, `kd_arrow_rate`, `kd_tab_rate`, `kd_digraph_simhash`, `total_keystrokes`, `session_duration_s` — is nullable by design because the **ingester that populates them does not exist yet** (documented as gap #2 in `SIGNAL_CAPTURE_AUDIT.md`). Every session that gets recorded lands an empty row (or, today, no row at all) while the `[t, "i", d]` event stream in the shard carries every signal those columns exist to capture.

**Motivating case.** Given the last 14 keystrokes of one real session (the `wget scanme.nmap.orgh` sequence from shard `2026-04-24`), a manual pass over the "i" events trivially recovers:
- Coefficient of variation ≈ **0.74** — solidly in the human band (scripts <0.1, jittered tools 0.3-0.6, humans 0.7-1.5+).
- A **467 ms pause** before the URL argument — classic semantic-boundary "thinking pause" between the command verb and its argument. Bots don't emit these; they fire the whole pre-composed line at uniform cadence.
- Tight **intra-word bigrams** — `ge` 79 ms, `t<space>` 83 ms — muscle-memory transitions.
- Slow **start-of-action latency** — `w` → `g` at 225 ms, characteristic of "initiating a command" vs "executing" a remembered one.

All four signals fall out of the schema for free. CoV from `kd_iki_mean` + `kd_iki_stdev`. Semantic pauses from `kd_think_ratio`. Bigram timing from `kd_digraph_simhash`. The fourth (start-of-action latency) doesn't have a column yet — see "Schema extensions" below.

**Design:**

1. **Trigger.** Subscribe on the bus to `attacker.session.ended` *or* (pragmatic fallback until DEBT-031's deferred session-boundary topic lands) poll `Log` rows with `event_type = "session_recorded"` that lack a `SessionProfile(sid=sid)` companion row. The poll path is what ships first; wire the bus later without changing the ingester body.
2. **Read side.** For each (decky, service, sid), resolve the shard via the fallback-scan path already shipped in `323077b` (`api_get_transcript._find_shard_with_sid`). Extract only `[t, "i", d]` events — the per-session index built by `_get_index` already buckets events by sid, so this is O(keystrokes-in-sid), not O(shard).
3. **Feature extraction.** One bounded pass over the input events:
   - IATs: pairwise `events[i].t - events[i-1].t`, clipped at e.g. 10 s so genuine "went to get coffee" gaps don't destroy the stdev.
   - Control-key rates: count backspace / ^U / ^W / ^C / ^D / arrow / tab against `total_keystrokes`, ratios not raw counts.
   - Enter latencies: IAT of each `\r` relative to the previous non-`\r` input.
   - Burst / think ratios: fraction of IATs below 200 ms / above 1 s.
   - SimHash: 8-byte Hamming-comparable digest over the top-N digraphs, weighted by occurrence.
4. **Write side.** One `session_profile` upsert per sid. Idempotent on re-run (same sid → same row).
5. **Schema extensions** (motivated by the manual analysis above — not blocking v1 but worth adding in the same commit if the ingester gets scheduled):
   - `kd_start_of_action_latency_ms` — IAT of the first keystroke after each prompt redraw (or approximated by "first keystroke after an idle gap >1 s"). User's point 5.
   - `kd_pause_hist_burst / _think / _distracted` — three-bucket pause-length histogram (<200 ms / 200-1500 ms / >1500 ms), more discriminating than a flat burst-vs-think ratio. User's middle suggestion.
   - `kd_top_bigrams` JSON blob — top-N (bigram, count, mean_iat_ms) tuples. Complement to `kd_digraph_simhash` that answers "same typist in same mental state", not just "same typist". User's first suggestion.

**Non-negotiables:**
- Bounded by the existing 10 MB per-session shard cap; no new disk-free precheck needed.
- No PII beyond what the shard already stores. Raw keystroke `d` values (which include the attacker's passwords in the input stream) MUST NOT land in `SessionProfile` columns — only timing and frequency aggregates. Bigram SimHash uses *characters*, not *content* — but document this explicitly in the column docstring so a future contributor doesn't "improve" it into something that leaks.
- Idempotent: re-running the ingester on a sid that already has a `SessionProfile` row overwrites deterministically (same shard, same `[t,"i",d]` events → same features).
- `FakeBus` / poll-only must keep this functional when `DECNET_BUS_ENABLED=false` — mirrors the DEBT-031 rollout pattern.

**Acceptance:**
- Shipping a decky, running a real SSH session, disconnecting → within one ingester tick a `SessionProfile` row exists with non-null `kd_iki_mean`, `kd_iki_stdev`, `kd_burst_ratio`, `kd_think_ratio`, `total_keystrokes`, `session_duration_s`.
- The motivating-case wget session produces CoV ≈ 0.74 ± 0.05 when the ingester processes it — sanity check against the manual analysis.
- The AttackerDetail page surfaces at least `kd_iki_mean` + `kd_burst_ratio` somewhere in the keystroke-dynamics section, unblocking the "is this the same typist" hover story.

**Status:** Open. Depends on the shard-scan fallback (shipped in `323077b`) and `SessionProfile` schema (shipped with session recording v1). The bus-trigger path depends on DEBT-031's deferred `attacker.session.started/ended` topics, but poll-driven ingestion works today and can ship first.

### DEBT-035 — Artifacts written as the container uid, not the API's
**Files:** `decnet/services/ssh.py`, `decnet/services/telnet.py`, `decnet/templates/{ssh,telnet}/{Dockerfile,entrypoint.sh}`, `decnet/composer.py` (wherever bind mounts for `/var/lib/decnet/artifacts/**` are generated), `decnet/web/router/transcripts/api_get_transcript.py` (consumer).

Every decoy container that produces artifacts (session recordings, captured uploads, credential dumps) writes into a host bind-mount under `/var/lib/decnet/artifacts/{decky}/{service}/...`. The writer is whatever uid is running inside the container — typically `root` (uid 0 inside the container, which maps to the host's `root` or the container's own unprivileged `decnet` uid depending on the template's `USER` directive). The API, on the other hand, runs under whatever `--user` was passed to `decnet init` — `anti` on dev boxes, `decnet` in production.

On mismatch, the API process hits `PermissionError` the moment it tries to `stat()` the artifacts dir. The transcripts endpoint now soft-fails this into a 404 (shipped in `323077b`), which keeps the API up but still leaves the operator unable to view any session that was recorded before the mismatch was fixed by hand.

**Evidence (dev box, 2026-04-24):**
```
PermissionError: [Errno 13] Permission denied:
  '/var/lib/decnet/artifacts/omega-decky/ssh/transcripts'
```
Workaround: `sudo chown -R anti:anti /var/lib/decnet/artifacts`. Every new decky re-creates the dir as whatever uid the container uses, so the workaround has to be re-run — which doesn't scale.

**Design options (pick one, not all):**

1. **Container runs as the host API's uid.** `compose_fragment()` for every artifact-producing service injects `user: "{host_uid}:{host_gid}"` into the compose snippet, sourcing the uid/gid from whatever `DECNET_API_UID` / `DECNET_API_GID` the master detected at init time (or `id -u` / `id -g` of the current process at compose time). This is the cleanest but has the most blast radius — bind mounts need to be pre-chowned to that uid before the container starts, and some templates have `entrypoint.sh` steps that assume root (e.g. `setcap`, `chmod` of system files during service setup).

2. **Setgid bit on the artifacts tree + shared group.** `mkdir -p /var/lib/decnet/artifacts && chmod 2775 /var/lib/decnet/artifacts && chgrp decnet /var/lib/decnet/artifacts`. Every new file inherits the `decnet` group; the API (member of `decnet`) can read regardless of which uid wrote. Still requires each container to `chmod g+r` its output — sessrec/emitter code would need a small change to `umask(0002)` or explicit `fchmod` calls. Less invasive but fragile: any writer that forgets the umask silently regresses.

3. **Sidecar post-processor.** A long-running daemon under the API's uid `inotify`-watches `/var/lib/decnet/artifacts/**`, re-chowns new files on creation. Works without touching any template, but adds a new process and a race window between "file created" and "file readable by API". Not a great shape for an already-worker-heavy architecture.

**Recommendation:** option 1, with the init command handling the setup (mkdir the artifacts tree with mode 0775, group = `--group`, then propagate the uid/gid into the compose generator). Option 2 as a fallback where option 1 can't land (e.g. templates that genuinely need root inside the container, like the conpot ICS template).

**Acceptance:**
- A fresh `decnet init --user anti --group anti` → deploy a decky → exercise a recorded session → the API (running as `anti`) can read `/var/lib/decnet/artifacts/.../transcripts/sessions-*.jsonl` **without any manual chown**.
- The soft-fail path shipped in `323077b` stays as defence-in-depth — the API must never 500 on a permission mismatch, but it also shouldn't *need* to soft-fail on a healthy install.

**Status:** Open. Current workaround is `sudo chown -R <user>:<group> /var/lib/decnet/artifacts` after every new deploy; soft-fail in the transcripts endpoint keeps the API alive in the interim.

### DEBT-037 — Webhook delivery guarantees beyond MVP
**Files:** `decnet/webhook/` (**new**), `decnet/web/db/models/webhooks.py` (**new**), `decnet/web/router/webhooks/` (**new**).

The webhook worker (Wazuh / Shuffle / TheHive / n8n integration path) ships MVP-first: subscription CRUD + a `decnet webhook` worker that subscribes to the internal bus, forwards matching events as HTTP POSTs with HMAC-SHA256 signatures (`X-DECNET-Signature: sha256=<hex>`), and retries 3× with exponential backoff. Simple-mode UI exposes an enum of event families (`AttackerDetail` / `DeckyStatus` / `SystemStatus`); Advanced mode exposes raw bus-topic patterns. Payload bodies are the existing Pydantic response models — no new schema.

What MVP deliberately defers:

1. ~~**Circuit breaker.**~~ ✅ **Shipped 2026-04-24.** After `DECNET_WEBHOOK_CIRCUIT_THRESHOLD` (default 5) consecutive failures the worker calls `trip_webhook_circuit(uuid, ts)` — flips `enabled=False`, stamps `auto_disabled_at`, fires a reload. Operator clears the trip by re-enabling via PATCH, which zeros the counter and clears the stamp. UI surfaces `TRIPPED · <ts>` chip on the row; page header shows a `N TRIPPED` count.
2. **Dead-letter table.** Events that exhaust retries are dropped with a log line, not persisted. Operators can't replay a missed event after they fix their Shuffle flow. Minimum viable: `webhook_dead_letters(subscription_id, topic, payload_json, final_error, dropped_at)` with a TTL sweep, and `POST /webhooks/{id}/replay?since=...` to re-queue.
3. **Delivery audit log.** No persisted record of "what went where and when." Useful for compliance and for debugging "why didn't TheHive see that alert." Same table shape as dead-letter but success-path entries with retention knob.
4. **Batch delivery / coalescing.** Every event fires one HTTP POST. High-volume topics (`system.log` on a busy master) will happily saturate the egress. Post-MVP, add a bounded batch window (e.g. up to 50 events or 500 ms) and POST an envelope `{events: [...]}`.
5. **Per-subscription rate limiting.** An admin who subscribes to `>` gets every event DECNET ever emits. A token-bucket cap (requests/sec to a given destination) protects both the webhook worker and the destination from operator self-inflicted DoS.
6. **Template overrides.** Shuffle accepts the DECNET shape; TheHive wants an observable-style envelope; Wazuh wants a flat `decoder + field` shape. MVP ships one shape. Post-MVP: per-subscription Jinja-ish payload template, or a small set of named adapters (`"shape": "thehive" | "wazuh" | "raw"`).
7. **Secret rotation.** HMAC secret is stored plaintext in the DB and rotated by UPDATE. Post-MVP: encrypt at rest (using the existing JWT secret as KEK), dual-secret window during rotation so in-flight verifications don't fail.

**Non-negotiable even at MVP:**
- HMAC signing (already scoped in MVP — listed here only to clarify it's NOT on the deferred list).
- `DECNET_BUS_ENABLED=false` must leave the webhook worker functional in a degraded "disabled" mode that surfaces its state via the Workers panel, matching DEBT-031's pattern.
- Retry backoff MUST jitter; synchronized retries across a fleet of DECNET masters would be its own DoS.

**Status:** Not yet started. Opens alongside the webhook MVP commit — the MVP PR will reference this entry and the follow-up work will close items 1–7 in priority order (circuit breaker first, batch delivery last).

### DEBT-038 — SSH PAM cred-capture: known limitations
**Files:** `decnet/templates/ssh/auth-helper.c`, `decnet/templates/ssh/Dockerfile`.

The SSH cred-capture path that closes the "real OpenSSH doesn't log attempted passwords" gap (commit `d064125`) ships in the smallest, most-realistic mechanism available — a static `pam_exec.so` shim binary. That choice trades a handful of known limitations against the alternatives (custom C PAM module, eBPF, OpenSSH patch, all heavier and more fingerprintable). Documenting them here so the trade-offs are explicit and the migration paths are obvious if any of these actually bite.

1. **Helper binary visible on disk.** `/usr/sbin/auth-helper` exists at runtime; a rooted attacker with shell can `find` it. Mitigations in place: boring system-binary name, stripped, statically linked (`file` reports a generic ELF, no module/library hints). Future hardening if needed: stealth-pack via the existing `_build_stealth.py` mechanism (XOR+gzip+base64 in `/entrypoint.sh`, write to disk at container start) — same pattern `syslog_bridge.py` and `emit_capture.py` already use. Skipped in v1 because the binary still has to exist on disk for `pam_exec` to invoke it; stealth packing only adds extraction complexity without reducing the exposed surface.

2. **PAM line fingerprinty.** `/etc/pam.d/sshd` shows `auth optional pam_exec.so expose_authtok stdout /usr/sbin/auth-helper`. Real ops use this exact pattern (Duo, Okta, custom MFA), so the line itself is not honeypot-screaming — but a sophisticated adversary reading PAM stacks against a known-good baseline will notice an unusual binary path. No clean mitigation short of the full custom-`.so` migration in (3).

3. **Fork-per-attempt DoS.** Every auth attempt forks `auth-helper`. Bounded above by sshd's `MaxStartups` and `LoginGraceTime` defaults; not exploitable in practice but real at extreme attempt rates (multi-thousand-per-second hydra runs against a single decky). Migration if it bites: a custom `pam_decnet_capture.so` writing via direct syscall without the fork. The PAM line stays identical (`auth optional pam_decnet_capture.so` with the same `expose_authtok`); only the binary type changes. Same wire format on the way out — no collector or dashboard work.

4. **Pubkey attempts not captured.** Pubkey auth runs through a separate PAM path; password-only is v1 by intent. Capturing pubkey attempt fingerprints (key-type, comment, fingerprint hash) needs a parallel hook into sshd's pubkey path, not pam_exec. Valuable signal but lower reuse density than passwords — defer until v2 or until cred-reuse analytics surface a need.

5. **Telnet had the same gap — closed in commit `f1026b4`.** Telnet's busybox-telnetd → `/bin/login` PAM stack didn't log attempted passwords either; the `auth-helper` binary is service-agnostic and was extended into `/etc/pam.d/login` via the same one-line PAM hook. The canonical source moved to `decnet/templates/_shared/auth-helper/auth-helper.c` and is synced into both ssh/ and telnet/ build contexts via `_sync_auth_helper_sources()` (mirrors the existing sessrec sync). Limitations 1–4 above apply equally to the telnet hook.

6. **Standardized SD shape (DEBT-039 follow-up).** The auth-helper SD-block now emits the universal `principal` + `secret_printable` + `secret_b64` keys consumed directly by the ingester's native-shape branch and stored as hoisted columns on the new `Credential` table. `username` rides alongside as a service-specific identity field for SSH/Telnet. Future emitters drop `username` in favor of their service-native identity (`domain` for SMTP, `dn` for LDAP, …).

**Status:** Open — document-only ticket tracking the architectural trade-offs of the v1 implementation. None of these are blocking; they're the things to know if the helper ever needs upgrading.

### ~~DEBT-039 — Migrate FTP/POP3/IMAP/SMTP emitters to standardized credential shape~~ ✅ RESOLVED

Closed by commits `aebb9f8` (encode_secret() helper), `abb4dd9` (six-service migration), and the legacy-adapter removal commit. Scope expanded during execution to include Redis (`auth, password=` — was silently dropped) and LDAP (`bind, dn=, password=` — was silently dropped) — both now emit the universal shape and feed the native ingester branch. The legacy adapter `_ingest_credential_legacy` and its `username`+`password` fork are deleted; only the native branch remains. Also added: the SMTP MAIL FROM event now exposes a parsed `domain=` field alongside the original `value=` for future "what domains attackers spoof from" analytics — Log row only, no Credential write.

---

### DEBT-040 — RDP, SMB, RDP-NLA cred capture (protocol framers)
**Files:** `decnet/templates/rdp/server.py`, `decnet/templates/smb/server.py`, `decnet/templates/_shared/ntlmssp.py` (already shipped).

Three protocol-heavy templates still capture only connection bytes; their wire format carries credentials we currently throw away:

1. **SMB** — `SimpleSMBServer` (Impacket) handles auth opaquely. NTLMSSP Type 3 messages carrying the NTLMv1/v2 hash flow through without ever surfacing in the `Credential` table. To fix: replace SimpleSMBServer with a hand-rolled asyncio SMB2 framer that (a) responds to Negotiate Protocol with a stock dialect, (b) responds to the first Session Setup with a stock NTLMSSP Type 2 challenge, (c) parses the second Session Setup's NTLMSSP Type 3 via the already-shipped `_shared/ntlmssp.py:parse_type3()`, (d) returns STATUS_LOGON_FAILURE so the attacker can't actually authenticate. Rough budget: 200 LoC for the SMB2/SPNEGO framer, parser is already there. Lands creds as `secret_kind="ntlmssp_v2"`.

2. **RDP basic auth** — `templates/rdp/server.py` accepts an X.224 connection but immediately drops the connection on data. To capture TS_LOGON_INFO (the legacy plaintext-recoverable auth that pre-NLA mstsc and old Hydra/MSF modules use), the template needs TPKT → X.224 Data PDU → MCS Send Data Request → Client Info PDU framing. Plaintext-recoverable, lands as `secret_kind="plaintext"`. Rough budget: 150 LoC. Limited operator value — most modern attackers default to NLA — but ships with Phase 4 of the original cred-coverage plan.

3. **RDP NLA / CredSSP** — the realistic-attacker path. RDP NLA wraps CredSSP, which wraps a TLS handshake, which carries SPNEGO/NTLM blobs. To capture: respond to the Connection Request advertising `PROTOCOL_HYBRID`, upgrade the socket to TLS using a self-signed cert (existing `https/` infra reusable), parse the inner CredSSP TSRequest ASN.1 DER, extract the negoTokens (NTLMSSP Type 1/2/3), reuse `_shared/ntlmssp.py:parse_type3()` for the Type 3 hash. Rough budget: 250 LoC, biggest of the three.

**Already shipped as Phase 5/7 prep:** `decnet/templates/_shared/ntlmssp.py` (Type 3 parser with 7 unit tests). Both SMB and RDP-NLA work consume it directly.

**Status:** Open — substantial protocol implementations each. Land independently as separate commits when scheduling allows. Cred-reuse analytics already work without these (the existing 12 services cover the bulk of attacker traffic); these three just round out fleet coverage.

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
| DEBT-033 | 🟡 Medium | Storage / Session recording | open |
| DEBT-035 | 🟡 Medium | Artifacts / Filesystem perms | open |
| DEBT-036 | 🟡 Medium | Correlation / Keystroke dynamics | open |
| DEBT-037 | 🟡 Medium | Integration / Webhooks | open (tracks MVP follow-ups) |
| DEBT-038 | 🟡 Medium | Honeypot / SSH cred capture | open (document-only) |
| ~~DEBT-039~~ | ✅ | Honeypot / Cred emitters | resolved |
| DEBT-040 | 🟡 Medium | Honeypot / RDP+SMB cred framers | open |

**Remaining open:** DEBT-011 (Alembic), DEBT-023 (image pinning), DEBT-026 (modular mailboxes), DEBT-027 (Dynamic bait store), DEBT-028 (deploy endpoint tests), DEBT-032 (fingerprint rotation detection), DEBT-033 (transcript shard rotation), DEBT-035 (artifacts uid/gid alignment), DEBT-036 (session-profile ingester), DEBT-037 (webhook delivery hardening), DEBT-038 (SSH PAM cred-capture limitations — document-only), DEBT-040 (RDP / SMB / NLA cred framers).
**Estimated remaining effort:** ~24 hours. DEBT-030 Phase B (optimistic staged-buffer editor) is a follow-up, not debt.
