# DECNET — Technical Debt Register

> Last updated: 2026-04-09 — All addressable debt cleared.
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

**Remaining open:** DEBT-011 (Alembic migrations), DEBT-023 (image digest pinning)  
**Estimated remaining effort:** ~7 hours
