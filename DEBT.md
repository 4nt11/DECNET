# DECNET — Technical Debt Register

> Last updated: 2026-04-09 (DEBT-001, DEBT-002, DEBT-004 resolved; DEBT-003 closed as false positive)  
> Severity: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low

---

## 🔴 Critical

### ~~DEBT-001 — Hardcoded JWT fallback secret~~ ✅ RESOLVED
~~**File:** `decnet/env.py:15`~~  
Fixed in commit `b6b046c`. `DECNET_JWT_SECRET` is now required; startup raises `ValueError` if unset or set to a known-bad value.

### ~~DEBT-002 — Default admin credentials in code~~ ✅ RESOLVED
~~**File:** `decnet/env.py:21-22`, `decnet/web/sqlite_repository.py:71`~~  
Fixed in commit `b6b046c`. `DECNET_ADMIN_PASSWORD` is now required via `_require_env()`; known-bad defaults are rejected at startup.

### ~~DEBT-003 — Hardcoded LDAP password placeholder~~ ✅ CLOSED (false positive)
`templates/ldap/server.py:73` — `"<sasl_or_unknown>"` is a log label for SASL auth attempts, not an operational credential. The LDAP template is a honeypot; it has no bind password of its own.

### ~~DEBT-004 — Wildcard CORS with no origin restriction~~ ✅ RESOLVED
~~**File:** `decnet/web/api.py:48-54`~~  
Fixed in commit `b6b046c`. `allow_origins` now uses `DECNET_CORS_ORIGINS` (env var, defaults to `http://localhost:8080`). `allow_methods` and `allow_headers` tightened to explicit allowlists.

---

## 🟠 High

### DEBT-005 — Auth module has zero test coverage
**File:** `decnet/web/auth.py`  
Password hashing, JWT generation, and token validation are completely untested. A bug here silently breaks authentication for all users.

### DEBT-006 — Database layer has zero test coverage
**File:** `decnet/web/sqlite_repository.py`  
400+ lines of SQL queries, schema initialization, and business logic with no dedicated tests. The dynamic WHERE clause construction (`json_extract` with `# nosec B608` markers at lines 194, 220, 236, 401, 420) is particularly risky without tests.

### DEBT-007 — Web API routes mostly untested
**Files:** `decnet/web/router/` (all sub-modules)  
`test_web_api.py` has only 2 tests. Entire router tree (fleet, logs, bounty, stream, auth) has effectively no coverage. No integration tests for request/response contracts.

### DEBT-008 — Auth token accepted via query string
**File:** `decnet/web/dependencies.py:33-34`  
```python
query_params.get("token")
```
Tokens in query strings appear in server access logs, browser history, and HTTP referrer headers. Should be header-only (`Authorization: Bearer`).

### DEBT-009 — Inconsistent and unstructured logging across templates
**Files:** All 20 service templates (`templates/*/server.py`)  
Every template uses `print(line, flush=True)` instead of the logging module or the existing `decnet_logging.py` helpers. This makes log parsing, filtering, and structured aggregation to ELK impossible without brittle string matching.

### DEBT-010 — `decnet_logging.py` duplicated across all 19 service templates
**Files:** `templates/*/decnet_logging.py`  
19 identical copies of the same logging helper file. Any fix to the shared utility requires 19 manual updates. Should be packaged and installed instead.

---

## 🟡 Medium

### DEBT-011 — No database migration system
**File:** `decnet/web/sqlite_repository.py:32-76`  
Schema is created ad-hoc during object construction in `_initialize_sync()`. There is no Alembic or equivalent migration layer. Schema changes across deployments require manual intervention or silently break existing databases.

### DEBT-012 — No environment variable validation schema
**File:** `decnet/env.py`  
`.env.local` and `.env` are loaded but values are not validated against a schema. Port numbers (`DECNET_API_PORT`, `DECNET_WEB_PORT`) are cast to `int` without range checks. No `.env.example` exists to document required vars. Missing required vars fail silently with bad defaults.

### DEBT-013 — Unvalidated input on `decky_name` route parameter
**File:** `decnet/web/router/fleet/api_mutate_decky.py:10`  
`decky_name: str` has no regex constraint, no length limit, and is passed downstream to Docker/shell operations. Should be validated against an allowlist pattern (e.g., `^[a-z0-9\-]{1,64}$`).

### DEBT-014 — Streaming endpoint has no error handling
**File:** `decnet/web/router/stream/api_stream_events.py`  
`async def event_generator()` has no try/except. If the database call inside fails, the SSE stream closes with no error event to the client and no server-side log entry.

### DEBT-015 — Broad exception detail leaked to API clients
**File:** `decnet/web/router/fleet/api_deploy_deckies.py:78`  
```python
detail=f"Deployment failed: {e}"
```
Raw exception messages (which may contain paths, hostnames, or internal state) are returned directly to API clients. Should log the full exception server-side and return a generic message.

### DEBT-016 — Unvalidated log query parameters
**File:** `decnet/web/router/logs/api_get_logs.py:12-19`  
`search`, `start_time`, `end_time` are passed directly to the repository without sanitization or type validation. No rate limiting exists on log queries — a high-frequency caller could cause significant DB load.

### DEBT-017 — Silent DB lock retry during startup
**File:** `decnet/web/api.py:20-26`  
DB initialization retries 5 times on lock with `asyncio.sleep(0.5)` and swallows the exception silently. No log warning is emitted. Startup failures are invisible unless the process exits.

### DEBT-018 — No Docker HEALTHCHECK in any template
**Files:** All 20 `templates/*/Dockerfile`  
No `HEALTHCHECK` directive. Docker Compose and orchestrators cannot detect service degradation and will not restart unhealthy containers automatically.

### DEBT-019 — Most template containers run as root
**Files:** All `templates/*/Dockerfile` except Cowrie  
No `USER` directive. Containers run as UID 0. A container escape would grant immediate root on the host.

### DEBT-020 — Swagger/OpenAPI disabled in production
**File:** `decnet/web/api.py:43-45`  
Docs are hidden unless `DECNET_DEVELOPER=true`. Several endpoints are missing `response_model` declarations, and no 4xx/5xx error responses are documented anywhere.

### DEBT-021 — `sqlite_repository.py` is a god module
**File:** `decnet/web/sqlite_repository.py` (~400 lines)  
Handles logs, users, bounties, statistics, and histograms in a single class. Should be split by domain (e.g., `UserRepository`, `LogRepository`, `BountyRepository`).

---

## 🟢 Low

### DEBT-022 — Debug `print()` in correlation engine
**File:** `decnet/correlation/engine.py:20`  
```python
print(t.path, t.decky_count)
```
Bare debug print left in production code path.

### DEBT-023 — Unpinned base Docker images
**Files:** All `templates/*/Dockerfile`  
`debian:bookworm-slim` and similar tags are used without digest pinning. Image contents can silently change on `docker pull`, breaking reproducibility and supply-chain integrity.

### DEBT-024 — Stale service version hardcoded in Redis template
**File:** `templates/redis/server.py:15`  
`REDIS_VERSION="7.0.12"` is pinned to an old release. Should be configurable or updated to current stable.

### DEBT-025 — No lock file for Python dependencies
**Files:** Project root  
No `requirements.txt` or locked `pyproject.toml` dependencies. `pip install -e .` resolves to latest-compatible versions at install time, making builds non-reproducible.

---

## Summary

| ID | Severity | Area | Effort |
|----|----------|------|--------|
| ~~DEBT-001~~ | ✅ | Security / Auth | resolved `b6b046c` |
| ~~DEBT-002~~ | ✅ | Security / Auth | resolved `b6b046c` |
| ~~DEBT-003~~ | ✅ | Security / Infra | closed (false positive) |
| ~~DEBT-004~~ | ✅ | Security / API | resolved `b6b046c` |
| DEBT-005 | 🟠 High | Testing | 4 hr |
| DEBT-006 | 🟠 High | Testing | 6 hr |
| DEBT-007 | 🟠 High | Testing | 8 hr |
| DEBT-008 | 🟠 High | Security / Auth | 1 hr |
| DEBT-009 | 🟠 High | Observability | 4 hr |
| DEBT-010 | 🟠 High | Code Duplication | 2 hr |
| DEBT-011 | 🟡 Medium | DB / Migrations | 6 hr |
| DEBT-012 | 🟡 Medium | Config | 2 hr |
| DEBT-013 | 🟡 Medium | Security / Input | 1 hr |
| DEBT-014 | 🟡 Medium | Reliability | 1 hr |
| DEBT-015 | 🟡 Medium | Security / API | 30 min |
| DEBT-016 | 🟡 Medium | Security / API | 2 hr |
| DEBT-017 | 🟡 Medium | Reliability | 30 min |
| DEBT-018 | 🟡 Medium | Infra | 2 hr |
| DEBT-019 | 🟡 Medium | Security / Infra | 2 hr |
| DEBT-020 | 🟡 Medium | Docs | 3 hr |
| DEBT-021 | 🟡 Medium | Architecture | 4 hr |
| DEBT-022 | 🟢 Low | Code Quality | 5 min |
| DEBT-023 | 🟢 Low | Infra | 1 hr |
| DEBT-024 | 🟢 Low | Infra | 15 min |
| DEBT-025 | 🟢 Low | Build | 1 hr |

**Total estimated remediation effort:** ~58 hours  
**Urgent (Critical + High):** ~28 hours  
**Resolved:** DEBT-001, DEBT-002, DEBT-003 (false positive), DEBT-004 — remaining urgent effort ~25 hours
