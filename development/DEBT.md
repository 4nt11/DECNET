# DECNET — Technical Debt Register

> Last updated: 2026-05-03 — DEBT-047 (R0047 BEC disk-reach)
> RESOLVED: shared `decnet/artifacts/paths.py` helper extracted,
> EmailLifter now disk-reaches `.eml` bodies in-process so the
> abstracted bus only carries `(decky_id, stored_as)`, and `decnet
> ttp` is unlocked on agents. 2026-05-02: DEBT-035 (artifacts
> uid/gid) RESOLVED via setgid + group-write on the artifacts root,
> which lifted the DEBT-047 filesystem-access blocker. Same-day:
> merged the rogue root-level DEBT.md into this canonical register;
> filed DEBT-044…DEBT-049 (email producer wiring + EmailLifter
> follow-ups + TTP recurring + Sigma post-v1).
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

### ~~DEBT-026 — IMAP/POP3 bait emails not configurable via service config~~ ✅ RESOLVED
**Files:** `templates/imap/server.py`, `templates/pop3/server.py`, `decnet/services/imap.py`, `decnet/services/pop3.py`
Resolved 2026-05-03. `IMAP_EMAIL_SEED` / `POP3_EMAIL_SEED` now accept either a directory (rglob `*.eml` and `*.json`) or a single `.json` / `.eml` file. JSON entries are dicts with required keys `from_addr`, `to_addr`, `subject`, `body` (optional `from_name`, `date`, `flags`); bare-body entries are wrapped into RFC 5322 on load. Loaded entries CONCATENATE with `_BAIT_EMAILS` (additive to the realism-engine emailgen output — the hardcoded baits are no longer replaced). `compose_fragment()` reads `service_cfg["email_seed"]` and bind-mounts the host path read-only at `/var/spool/decnet-emails/seed`. When `email_seed` is unset, the compose fragment falls back to `$PROJROOT/bait/` if that directory exists — operators can drop a deployment-wide bait corpus there without touching per-decky config.

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
- **Standalone graph-correlator worker** — closed. The original rollout plan presumed one; the graph engine instead lives as library code in `decnet/correlation/` and is consumed by the profiler worker (graph traversal during profiling) and the reuse correlator (credential-reuse pass). The dead `decnet correlate` CLI debug helper has been removed. Library shape is the right one — keeping it.
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

### ~~DEBT-035 — Artifacts written as the container uid, not the API's~~ ✅ RESOLVED 2026-05-02
**Files:** `decnet/cli/init.py`, `decnet/web/router/transcripts/api_get_transcript.py` (soft-fail kept as defence-in-depth).

The original recommendation was option 1 (compose `user:` directive
sourcing the API uid/gid). On implementation that turned out to be
infeasible for two of the artifact-producing templates: SSH and
Telnet *fundamentally* need root inside the container because PAM
authentication uses `setuid(2)` to switch to the target user during
login, and a non-root `sshd` / `/bin/login` cannot do that. So
option 1 doesn't generalise.

Option 2 (setgid bit + shared group) does generalise, and after
exploration it turned out to be **load-bearing on its own** — no
compose `user:` directive is required:

1. `decnet init` now creates `/var/lib/decnet/artifacts` with mode
   `0o2775` (setgid + group-write) owned by the DECNET-service
   `user:group` (commit `b2733216`).
2. Linux `mkdir(2)` propagates the setgid bit AND the parent's
   group to every new subdirectory, so when Docker auto-creates
   `/var/lib/decnet/artifacts/{decky}/{service}/...` for a bind-
   mount, those subdirs come up with `group=decnet` and the setgid
   bit set.
3. Containers write files with default umask `0o022`, which yields
   mode `0o644` (group-readable). The file's group is `decnet`
   (inherited via setgid).
4. The API process (and the local TTP worker on an agent) runs as
   the DECNET-service user, whose primary group is `decnet` →
   group-read on the file is satisfied → no manual chown.

`decnet/cli/init.py` also persists the resolved user / group as
**names** under `[decnet] api-user` / `api-group` in `decnet.ini`
(commit `39a298f6`). The kebab keys auto-translate to
`DECNET_API_USER` / `DECNET_API_GROUP` env vars via
`decnet/config_ini.py` at runtime, available to any future composer
or worker that needs to resolve the local uid via `pwd.getpwnam`
(deferred — not needed for this paydown, kept as the cleaner path
if a stricter security model is wanted later).

**Acceptance verified**: fresh `decnet init --user anti --group anti
--prefix tmp` → `/var/lib/decnet/artifacts` lands at mode `0o2775`
owned by `anti:anti`. Subsequent decoy auto-create propagates the
group + setgid; files written 0o644 are readable by `anti`.

**Defence-in-depth retained**: the soft-fail path in
`api_get_transcript.py` and `api_get_artifact.py` stays — option 2
makes it never fire on a healthy install but a misconfigured deploy
must still not 500 the API.

**Out of scope (filed as separate follow-ups)**:
- Compose `user:` directive injection per fragment (option 1).
  Optional polish for the 24 templates that already drop to
  `logrelay`. SSH and Telnet are blocked on PAM/setuid as noted
  above. File as a fresh DEBT entry if a stricter "container uid
  matches host uid" model is wanted.
- `decnet ttp` master-only gate flip (`decnet/cli/gating.py:28–34`).
  Required for DEBT-047 to land (TTP worker on agents reads `.eml`
  files), but a separate one-line change with its own test. File
  alongside the DEBT-047 disk-reach implementation.

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

### ~~DEBT-040 — RDP, SMB, RDP-NLA cred capture (protocol framers)~~ ✅ RESOLVED
**Files:** `decnet/templates/smb/server.py` (rewritten), `decnet/templates/rdp/server.py` (rewritten), `decnet/engine/deployer.py` (`_sync_ntlmssp_sources()`), `decnet/services/rdp.py` (`nla` knob), `tests/service_testing/test_smb_server.py` + `test_rdp_basic.py` + `test_rdp_nla.py`.

Closed in three commits on `dev`:

1. **SMB NTLMSSP framer.** `SimpleSMBServer` replaced with a hand-rolled asyncio SMB2 framer that walks Negotiate → SessionSetup(Type 1) → SessionSetup(Type 3); reuses the shared `parse_type3()` to land `secret_kind="ntlmssp_v2"` (or `_v1`) in the Credential table. Always returns `STATUS_LOGON_FAILURE`. SPNEGO Type 2 challenge is wrapped per RFC 4178; per-decky `SERVER_CHALLENGE` derived from `instance_seed.random_bytes("ntlm_challenge")` so the fleet doesn't share a fingerprint. Impacket dependency dropped. 7 unit tests.

2. **RDP X.224 cookie capture.** The Twisted-based connection logger replaced with an asyncio handler that parses the X.224 Connection Request, extracts the `mstshash=<user>` routing cookie (stamped by mstsc / FreeRDP / Hydra / ncrack / MSF `rdp_login`), records `rdpNegRequest.requestedProtocols`, and answers with a well-formed Connection Confirm selecting `PROTOCOL_RDP`. Scope-down vs. the original spec: full `TS_INFO_PACKET` extraction would have required either Standard-RDP-Security RC4 (with our own RSA pair + MS-RDPBCGR signing) or a complete MCS+GCC ASN.1/BER stack — both far beyond the 150 LoC budget. The cookie is the only credential bit that flows in plaintext on the wire; capturing it is the highest-value-per-byte signal without those rabbit holes. 7 unit tests.

3. **RDP NLA / CredSSP.** Behind `RDP_ENABLE_NLA=true` (or `service_cfg.nla=true` in the topology), confirms `PROTOCOL_HYBRID`, upgrades the socket to TLS via `loop.start_tls()` using a self-signed cert generated by the entrypoint, then drives a tiny CredSSP loop: read inbound TSRequest DER, scan for the NTLMSSP signature, dispatch on message type — Type 1 → respond with TSRequest carrying a Type 2 challenge; Type 3 → `parse_type3()` and emit. Hand-built TSRequest writer (no `pyasn1` dep). 9 unit tests (DER reader, builder, `_handle_nla` round-trip, oversized-DER drop, per-instance challenge differs across `NODE_NAME`).

Shared prep landed in commit 1: `_sync_ntlmssp_sources()` in `decnet/engine/deployer.py` mirrors the auth-helper / sessrec sync pattern, copies `_shared/ntlmssp.py` into the SMB and RDP build contexts before `docker compose up`.

**Deferred (not blocking close):**
- Full `TS_INFO_PACKET` (basic-RDP plaintext password) — see scope-down note in commit 2. Re-open as a follow-up DEBT if attacker telemetry actually shows traffic on `PROTOCOL_RDP` without NLA.
- Pubkey / Kerberos auth paths — out of scope; mirrors DEBT-038's deferral on the SSH side.

### ~~DEBT-041 — Intel API + UI keyed by attacker.ip, not attacker.uuid~~ ✅ RESOLVED
Closed by re-key commit on `dev`. `attacker_intel.attacker_uuid` is now the canonical key (UNIQUE + FK to `attackers.uuid`); `attacker_ip` stays as a denormalised value column (indexed, not unique). `GET /api/v1/attackers/{uuid}/intel` is the only public route — the IP-keyed alias was deleted, not deprecated. Bus event `attacker.intel.enriched` payload gains `attacker_uuid` alongside `attacker_ip` for SIEM consumers. `<IntelPanel uuid={...} />` swaps to UUID. The ticket text below is preserved as the original rationale.

**Files:** `decnet/web/router/attackers/api_get_attacker_intel.py`, `decnet/web/db/sqlmodel_repo.py:upsert_attacker_intel`, `decnet/web/db/models/attacker_intel.py`, `decnet_web/src/components/AttackerDetail.tsx` (`<IntelPanel ip={attacker.ip} />`).

The threat-intel enrichment surface (DEBT-N/A: `feat(intel)` series) keys every public surface — `GET /api/v1/attackers/{ip}/intel`, the row's `attacker_ip` UNIQUE, and the React `<IntelPanel ip=...>` — on the attacker's IP rather than the canonical `attacker.uuid` we use for every other attacker-detail route. The decision was deliberate in v1: the enricher is woken by `attacker.observed` / `attacker.scored` events whose payload is naturally IP-keyed, the row models a *one-row-per-IP* TTL cache, and standing up a parallel UUID lookup endpoint would have added a join hop with no consumer.

**Why this is debt, not just a design choice:**
1. **NAT / shared-egress collisions.** Two distinct attacker UUIDs that share a source IP (corporate NAT, mobile carrier CGNAT, open VPN exit) collapse to one intel row. Verdicts are technically "about the IP" so this is correct semantically, but the AttackerDetail surface implies *this attacker's intel*, which is misleading when an actor swap goes unnoticed. A UUID-keyed view would let the UI show "this row is shared with N other attacker profiles" honestly.
2. **API consistency.** Every other route under `/api/v1/attackers/` is keyed by UUID (`/{uuid}/commands`, `/{uuid}/artifacts`, `/{uuid}/transcripts`, etc.). The IP-keyed `/{ip}/intel` is an outlier that contract-test scaffolding (Schemathesis path-param fuzzing) and OpenAPI-driven SDKs will trip over.
3. **Federation-shape mismatch.** DEVELOPMENT_V2's federation work expects gossip-able fingerprints attached to *identity vectors* (session profiles, simhash), not IP-keyed rows. When the federation layer lands and starts asking "what intel exists for this attacker?", the answer is currently a join through the IP — fine, but the abstraction leaks.
4. **AttackerDetail.tsx coupling.** `<IntelPanel ip={attacker.ip} />` requires the parent fetch (UUID-keyed) to land before the panel can fire its own request. Two sequential fetches where one would suffice if the panel were UUID-keyed and either (a) the row carried `attacker_uuid` as a queryable index or (b) the endpoint accepted a UUID and performed the IP join server-side.

**Migration sketch (post-v1):**
1. Add `GET /api/v1/attackers/{uuid}/intel` — server-side resolves `uuid → ip`, then `ip → AttackerIntel` row. Keep the IP-keyed route as a deprecated alias for two release cycles.
2. Frontend switches `<IntelPanel uuid={...} />` and the parallel-fetches via `Promise.all` with the existing `useEffect`s.
3. Decide whether the `attacker_intel` table grows a real foreign key on `attacker_uuid` (with the NAT-collision implications above made explicit in the model docstring) OR whether the row stays IP-keyed and the endpoint just performs the join — the latter is cheaper, the former gives stronger guarantees if/when we want to delete intel rows on attacker purge.

**Acceptance:**
- `/api/v1/attackers/{uuid}/intel` returns the intel row for the attacker's *current* IP, with a clear contract on what happens when an attacker has rotated IPs (see follow-up open question).
- The IP-keyed route returns `Deprecation:` header and is removed in v1.2 or v2.0 once external integrations migrate.
- AttackerDetail.tsx stops passing `attacker.ip` into `<IntelPanel/>`.

**Open question:** for an attacker UUID whose row currently carries IP `A` but who first appeared from IP `B`, what should `/attackers/{uuid}/intel` return? Most-recent-IP (current behavior implicit through `attacker.ip`) is the v1 answer; "all intel rows ever associated with this attacker" might surface IP rotation more clearly in a v2 surface. Decide before the migration ships, document either way.

**Status:** Open. No operational impact today (single-IP attackers are the dominant case), but worth closing before the federation layer lands so the wire-format and API both speak in identity terms, not IP terms.

### ~~DEBT-032 — Attacker fingerprint rotation detection~~ ✅ RESOLVED
**Files:** `decnet/correlation/fingerprint_rotation.py` (new), `decnet/prober/worker.py`, `decnet/web/db/models/attackers.py`, `decnet/bus/topics.py`.

Resolved 2026-05-03. **Reframed during planning:** the original entry described this as a per-decky substrate-integrity problem, but the prober probes *attackers*, not deckies. The actual gap was attacker substrate tracking — same attacker IP rotating their VPS, rebuilding their SSH server, swapping their TLS cert — invisible at correlator-time because nothing diffed consecutive hashes for the same `(attacker_ip, port, probe_type)` triple.

Implemented as a small library (`decnet.correlation.fingerprint_rotation.record_fingerprint`) called inline from the prober at each of the three emit sites (JARM / HASSH / TCPFP). No new worker daemon; the prober is still the only producer, just teaches it to derive a second event on hash flip. New `AttackerFingerprintState` table holds per-`(attacker_uuid, port, probe_type)` last-hash state. New bus topic `attacker.fingerprint_rotated` carries `{attacker_uuid, attacker_ip, port, probe_type, old_hash, new_hash, rotation_count, ts}`. `Attacker.rotation_count` and `Attacker.last_rotation_at` are stamped on every diff so the dashboard can render rotation telemetry without joining. Library is fully sync + unit-tested with injected publish_fn / syslog_fn callbacks.

Out of scope (deferred): dashboard surfacing of `rotation_count`; attribution clustering across attackers (same JARM seen from different IPs); backfill from existing event store.

---

## 🟢 Low

### ~~DEBT-022 — Debug `print()` in correlation engine~~ ✅ CLOSED (false positive)
`decnet/correlation/engine.py:20` — The `print()` call is inside the module docstring as a usage example, not in executable code. No production code path affected.

### ~~DEBT-023 — Unpinned base Docker images~~ ✅ RESOLVED
**Files:** `decnet/distros.py`, `decnet/models.py`, `decnet/topology/compose.py`, `decnet/services/conpot.py`, all `decnet/templates/*/Dockerfile`
Resolved 2026-05-03. All base images now carry `image:tag@sha256:<digest>` references. Tags retained for human readability; `@sha256` is what Docker actually resolves, so a registry-side rebuild can no longer swap content under us. Pinned: `debian:bookworm-slim`, `ubuntu:22.04`, `ubuntu:20.04`, `rockylinux:9-minimal`, `centos:7`, `alpine:3.19`, `fedora:39`, `kalilinux/kali-rolling`, `archlinux:latest`, `honeynet/conpot:latest`. Refresh procedure documented at the top of `decnet/distros.py` (`docker pull <tag>` + `docker inspect --format '{{index .RepoDigests 0}}' <tag>`).

### ~~DEBT-024 — Stale service version hardcoded in Redis template~~ ✅ RESOLVED
~~**File:** `templates/redis/server.py:15`~~  
`REDIS_VERSION` updated from `"7.0.12"` to `"7.2.7"` (current stable).

### ~~DEBT-025 — No lock file for Python dependencies~~ ✅ RESOLVED
~~**Files:** Project root~~  
`requirements.lock` generated via `pip freeze`. Reproducible installs now available via `pip install -r requirements.lock`.

### ~~DEBT-042 — Orchestrator failure-count badge is window-bound~~ ✅ RESOLVED 2026-05-03
**Files:** `decnet/web/router/orchestrator/api_event_stats.py` (new),
`decnet/web/db/sqlmodel_repo/orchestrator.py`, `decnet/web/db/repository.py`,
`decnet_web/src/components/Orchestrator.tsx`.
New `GET /api/v1/orchestrator/events/stats?since=1h&success=false&kind=...`
endpoint backed by `repo.count_orchestrator_failures(since_ts, kind)`,
which counts failed rows across both `orchestrator_events` and
`orchestrator_emails` since the cutoff. The badge polls the endpoint
on mount + every 30 s and renders the authoritative DB-derived count
instead of deriving from the SSE buffer + one paginated page. Window
parser accepts `^\d+[smhd]$`, capped at 7d. Today only `success=false`
is accepted on this surface (the only consumer); other modes are
rejected so the endpoint isn't accidentally repurposed before the
next consumer is properly designed. Repo + endpoint + badge tests
land in the same commit.

### ~~DEBT-043 — No frontend test framework configured~~ ✅ RESOLVED 2026-05-03
**Files:** `decnet_web/package.json`, `decnet_web/vite.config.ts`,
`decnet_web/src/test/setup.ts`, `decnet_web/src/components/Orchestrator.test.tsx`.
vitest 4 + jsdom + @testing-library/{react,jest-dom,user-event} +
@vitest/coverage-v8 wired through `vite.config.ts` (using
`defineConfig` from `vitest/config` so the `test` block type-checks).
`src/test/setup.ts` registers jest-dom matchers and runs RTL
`cleanup` after each test. `tsconfig.app.json` picks up
`vitest/globals` + `@testing-library/jest-dom` types. New scripts:
`npm test` (watch), `npm run test:run` (one-shot), `npm run coverage`.
Seed suite (`Orchestrator.test.tsx`) exercises the three regressions
called out in the original entry: empty-state render, kind-filter
toggling triggers a scoped refetch, and a mocked stream callback
prepends a row to the table. Future component tests land alongside
`*.tsx` as `*.test.tsx`.

### ~~DEBT-044 — `attacker.email.received` producer not wired~~ ✅ RESOLVED
**Files:** `decnet/web/ingester.py`, `decnet/templates/smtp/server.py`
The TTP worker subscribed to `email.received` for the EmailLifter
(R0041–R0048) but no upstream component published the topic.
Originally deferred under the wrong premise that the SMTP-relay path
did not persist received emails to a DB table — in fact
`SMTPProtocol` persists every received message as a Bounty artifact
(`bounty_type="artifact" payload.kind="mail"`) at `ingester.py:596–615`
and `_summarize_message` already extracts headers + per-attachment
metadata.
Resolved 2026-05-02 in commits `e9324aca` (decky-side cheap
extractions: X-Mailer / Return-Path / Authentication-Results dkim+spf
/ URLs) and `fb857627` (ingester producer at
`_publish_email_received`). After paydown R0041 / R0043 / R0044 /
R0045 fire end-to-end; R0046 partial (extension lane). Heavyweight
follow-ups carved into DEBT-046 and DEBT-047.

### DEBT-045 — EmailLifter heavyweight feature extraction (R0042 / R0046 / R0048) — PARTIAL PAID 2026-05-02
**Files:** `decnet/templates/smtp/server.py`, `decnet/web/ingester.py`
Layer-2 extractors for R0042 / R0046 (macro / password / smuggling
lanes) / R0048 landed 2026-05-02 in commits `291b78c1` (decky
`_summarize_message` extension: inlined Charikar simhash, base64
byte counter, OOXML `vbaProject.bin` sniff, ZIP / 7z / RAR / CFBF
encrypted-archive detection, lxml structural HTML-smuggling parse
with regex fallback) and `c7149410` (ingester producer projection,
OR-reducing per-attachment booleans into top-level rule fields).
After paydown the bus payload carries `body_simhash`,
`body_base64_bytes`, `attachment_macros`,
`attachment_password_protected`, `html_smuggling`. R0042 / R0046
(three lanes) / R0048 fire end-to-end. The two remaining lanes
ride on DEBT-046 (mal_hash_match — needs a feed) and DEBT-047
(R0047 BEC — gated on artifact disk-reach, see DEBT-035).
**Status:** Partial. Closed except for the carved-out follow-ups.

### DEBT-046 — EmailLifter mal-hash feed integration (R0046 mal_hash_match)
**Files:** `decnet/intel/feodo.py` (template), `decnet/web/ingester.py` (consumer wiring), **new** `decnet/intel/mal_hash.py`
R0046's `mal_hash_match` lane stays gated until DECNET has a curated
bad-hash feed it can lookup attachment SHA-256s against. The
producer ships `attachment_sha256s: list[str]` on the bus today
(commit `c7149410`) but no provider resolves a `mal_hash_match: bool`.
**Design sketch** (mirrors `decnet/intel/feodo.py`'s bulk-feed pattern):
- Feed source: MalwareBazaar's public SHA-256 dump as the v0
  candidate (free, daily refresh, ~100 MB compressed). Operators
  with paid VT subscriptions can swap the provider behind the same
  factory.
- Storage: in-memory set keyed by sha256, TTL-cached on a slow
  refresh loop. Mirror `FeodoProvider`'s `_ensure_fresh` /
  `_refresh` shape exactly.
- Wiring: ingester reads each `attachment_sha256` in the manifest
  at `_publish_email_received` time, checks against the cached
  feed, sets `mal_hash_match: bool` on the bus payload.
- Rule pack: no rule changes. `_p_malicious_attachment` already
  reads `payload.get("mal_hash_match")` — silent today only because
  the field is absent.
**Trigger:** a curated feed source is selected (MalwareBazaar dump
or better) and the operator has bandwidth / disk for a fresh refresh
loop.
**Status:** Open. Owner TBD. Filed 2026-05-02 alongside DEBT-045.

### ~~DEBT-047~~ — EmailLifter R0047 BEC unblock (artifact disk-reach) ✅ RESOLVED 2026-05-03
**Files:** `decnet/artifacts/paths.py` (new shared helper),
`decnet/ttp/impl/email_lifter.py` (`_load_body_text` + `_extract_body_text`),
`decnet/web/router/artifacts/api_get_artifact.py` (refactored to import the
shared helper), `decnet/cli/gating.py` + `decnet/cli/ttp.py` (gate flipped).
R0047's predicate (`_p_bec` at `email_lifter.py:244`) reads
`body_text` and `subject`, substring-matching them against per-rule
keyword lists. Shipping raw body text on the abstracted service bus
is the wrong privacy stance — the bus transport is abstracted (the
UNIX-socket implementation today may swap to a networked transport
tomorrow), and treating "loopback today" as a license to ship PII
would bite the moment that swap happens.
The right solution is **disk-reach**: the EmailLifter on tag-time
opens the `.eml` from the artifact tree at
`/var/lib/decnet/artifacts/{decky}/smtp/{stored_as}` and runs the
predicate against the body parsed in-process. Bus carries only the
artifact pointer; raw body text never leaves the host disk
boundary.
**Filesystem access UNBLOCKED 2026-05-02 by DEBT-035 paydown** —
`/var/lib/decnet/artifacts` carries setgid + `decnet:decnet`, so
files written by SMTP decoys are group-readable by the local
DECNET-service user (which is what `decnet ttp` runs as on
agents). The legacy `_p_bec` body_text path remains in place
untouched, so when the disk-reach helper lands the predicate
works without any code change.
**Resolution (2026-05-03):**
- Extracted `resolve_artifact_path` + `ArtifactPathError` into the new
  `decnet/artifacts/paths.py` package, shared by the admin-gated
  download endpoint and the lifter. Symlink-escape check, regex
  validation, and `ARTIFACTS_ROOT` env override all live in the
  shared module.
- Added `_load_body_text(payload)` to `email_lifter.py`. When the
  bus payload omits `body_text` but carries `decky_id` + `stored_as`,
  the helper opens the `.eml` via stdlib `email` with
  `policy=email.policy.default` and walks parts (text/plain →
  text/html fallback). Decoded body is memoized into the payload
  dict so multiple body-aware predicates on the same event open
  the file once. Both `_p_bec` (R0047) and `_p_encoded_payload`
  route through the helper; the legacy inline `body_text` path is
  preserved as a fast path.
- Removed `"ttp"` from `MASTER_ONLY_COMMANDS` in `cli/gating.py`
  and dropped `_require_master_mode("ttp")` in `cli/ttp.py`.
  `ttp-backfill` (master DB walker) stays master-only.
- Tests: `tests/artifacts/test_paths.py`,
  `tests/ttp/test_email_lifter_disk_reach.py`,
  `tests/cli/test_gating_ttp_agent.py`.
**Status:** Resolved. Filed 2026-05-02 alongside DEBT-045; closed
2026-05-03.

### DEBT-048 — TTP intel provider mapping review (quarterly recurring)
**Files:** `rules/ttp/R0054.yaml`–`R0058.yaml`, `decnet/ttp/impl/intel_lifter.py`, `development/TTP_TAGGING.md` §"Hard parts §9 Intel provider drift".
AbuseIPDB occasionally adds new abuse categories. GreyNoise revises
its classification taxonomy. ThreatFox extends `threat_type` /
`ioc_type` enums. The intel_lifter's mapping tables are static
catalogues; they will fall behind reality unless re-walked on a
cadence. Each rule YAML carries `last_reviewed` / `next_review`
markers as the canonical record.
**Cadence:** every quarter, first week of the month. Trigger: rule
YAML `next_review` markers (canonical), with a calendar reminder
as backup.
**Operational runbook:** `development/TTP_TAGGING.md` §"Hard parts
§9 Intel provider drift" — provider URLs, ThreatFox auth-key curl
invocation, rule_version + emits + attack_catalog co-evolution
rules, drift-found vs no-drift commit shapes.
**Last reviewed:** **2026-05-02** (ship-time audit — see
`development/TTP_TAGGING.md` §9 "Ship-time audit log"; corrected
two AbuseIPDB code typos, expanded R0054 / R0055 / R0057 emits
lists to cover the full predicate technique universe, repointed
ThreatFox dispatch from `ioc_type` to `threat_type`, wired the
`AttackerIntel.{abuseipdb_categories, greynoise_tags,
greynoise_name, feodo_malware_family, threatfox_*_types,
threatfox_malware_families}` columns + producer parsing).
**Next review:** **2026-08-02**.
**Status:** Recurring. Owner: TTP rule maintainer (currently ANTI).

### DEBT-049 — TTP Sigma adapter — post-v1
**Files:** `decnet/ttp/impl/` (new engine), `rules/ttp/` (new rule subtree).
The Sigma rule format adapter is deferred to post-v1 per
`development/TTP_TAGGING.md` §"Tagging engines, layered §5". Lands
once v0 ships and the rule-precision targets stabilize so we have
a calibration reference for translated rules. Until then,
`decnet/ttp/impl/` does not gain a Sigma engine and `rules/ttp/`
stays YAML-only.
**Trigger:** v0 precision targets met + at least one downstream
user who needs it.
**Status:** Open. Owner TBD.

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
| ~~DEBT-023~~ | ✅ | Infra | resolved 2026-05-03 |
| ~~DEBT-024~~ | ✅ | Infra | resolved |
| ~~DEBT-025~~ | ✅ | Build | resolved |
| ~~DEBT-026~~ | ✅ | Features | resolved 2026-05-03 |
| DEBT-027 | 🟡 Medium | Features | deferred (out of scope) |
| DEBT-028 | 🟡 Medium | Testing | deferred (needs DinD CI) |
| DEBT-029 | 🟡 Medium | Architecture / Bus | ✅ resolved |
| DEBT-030 | 🟡 Medium | Web / Live mutations | ✅ resolved (Phase A) |
| ~~DEBT-031~~ | ✅ | Workers / Bus integration | resolved |
| ~~DEBT-032~~ | ✅ | Correlation / Prober | resolved 2026-05-03 |
| DEBT-033 | 🟡 Medium | Storage / Session recording | open |
| ~~DEBT-035~~ | ✅ | Artifacts / Filesystem perms | resolved 2026-05-02 |
| DEBT-036 | 🟡 Medium | Correlation / Keystroke dynamics | open |
| DEBT-037 | 🟡 Medium | Integration / Webhooks | open (tracks MVP follow-ups) |
| DEBT-038 | 🟡 Medium | Honeypot / SSH cred capture | open (document-only) |
| ~~DEBT-039~~ | ✅ | Honeypot / Cred emitters | resolved |
| ~~DEBT-040~~ | ✅ | Honeypot / RDP+SMB cred framers | resolved |
| ~~DEBT-041~~ | ✅ | API / UI / Threat-intel keying | resolved |
| ~~DEBT-042~~ | ✅ | UI / Orchestrator failure-count window | resolved 2026-05-03 |
| ~~DEBT-043~~ | ✅ | Frontend test framework missing | resolved 2026-05-03 |
| ~~DEBT-044~~ | ✅ | TTP / Email producer wiring | resolved 2026-05-02 |
| DEBT-045 | 🟡 Medium | TTP / EmailLifter heavyweight extraction | partial paid 2026-05-02 |
| DEBT-046 | 🟡 Medium | TTP / EmailLifter mal-hash feed integration | open |
| ~~DEBT-047~~ | ✅ | TTP / EmailLifter R0047 BEC (disk-reach) | resolved 2026-05-03 |
| DEBT-048 | 🟡 Medium | TTP / Intel provider mapping review (recurring) | open / recurring |
| DEBT-049 | 🟡 Medium | TTP / Sigma adapter (post-v1) | open |

**Remaining open:** DEBT-011 (Alembic), DEBT-027 (Dynamic bait store), DEBT-028 (deploy endpoint tests), DEBT-033 (transcript shard rotation), DEBT-036 (session-profile ingester), DEBT-037 (webhook delivery hardening), DEBT-038 (SSH PAM cred-capture limitations — document-only), DEBT-045 (EmailLifter heavyweight — partial paid; carved-out follow-ups remain), DEBT-046 (mal-hash feed), DEBT-048 (TTP intel provider mapping review — recurring quarterly), DEBT-049 (TTP Sigma adapter — post-v1).
**Estimated remaining effort:** ~21 hours plus the new EmailLifter / TTP follow-ups. DEBT-030 Phase B (optimistic staged-buffer editor) is a follow-up, not debt.
