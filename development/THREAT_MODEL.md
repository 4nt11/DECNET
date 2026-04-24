# DECNET Threat Model

## Purpose

This document is the single source of truth for **what threats DECNET
defends against, what it accepts, and what it considers out of scope.**

Its role is to provide a **stop line** for design discussions: once a
threat is recorded here with a status, it does not need to be
re-litigated in every feature review. New threats get added; existing
ones get re-classified if reality changes; nothing gets deleted without
a note in the change log.

## Methodology — STRIDE per-element

We use STRIDE-per-element (threats-per-element variant), organized by
**trust boundary**. Each major component gets:

1. A **data-flow diagram (DFD)** showing external entities, processes,
   data stores, and the trust boundaries that separate them.
2. A per-flow **STRIDE enumeration** — for each data flow crossing a
   trust boundary, identify threats in each of the six categories:

   | Code | Category | Violates |
   |------|----------|----------|
   | S | Spoofing | Authentication |
   | T | Tampering | Integrity |
   | R | Repudiation | Non-repudiation |
   | I | Information disclosure | Confidentiality |
   | D | Denial of service | Availability |
   | E | Elevation of privilege | Authorization |

3. **Mitigation status** for each threat, chosen from:

   - **Mitigated** — defended in code; link to the mitigation.
   - **Accepted** — the risk is known and deliberately accepted; note
     the reason.
   - **Transferred** — responsibility lies elsewhere (OS, upstream
     library, operator deployment practice).
   - **Needs verification** — plausibly mitigated but the threat model
     author couldn't confirm in code; flag for review.
   - **Out of scope** — explicitly excluded (see the master
     out-of-scope register).

## Risk-acceptance protocol

Accepting a risk is a deliberate act with a written justification. An
"accepted" entry must include:

- **Why** the risk is accepted (cost/benefit, compensating control
  elsewhere, low likelihood × low impact).
- **When** the acceptance should be revisited (e.g. "reassess when
  multi-tenant support lands" or "revisit pre-v1").
- **Who** observed and accepted it (by git commit author on this file —
  no hand-waving).

---

## System context

DECNET is a distributed honeypot platform. The top-level actors and
trust boundaries:

```
                           ┌─────────────────────────┐
                           │ External Attacker       │
                           │ (internet, untrusted)   │
                           └─────────────┬───────────┘
                                         │ TCP/IP (MACVLAN)
                                         ▼
  ── TRUST BOUNDARY: attacker ↔ decoy ──────────────────────────────
                                         │
                           ┌─────────────▼───────────┐
                           │ Decky (honeypot)        │
                           │ service containers      │
                           └─────────────┬───────────┘
                                         │ RFC 5424 syslog
                                         │ (local: UDP; cross-host: TLS 6514)
                                         ▼
  ── TRUST BOUNDARY: decky ↔ master (log ingest) ────────────────────
                                         │
                           ┌─────────────▼───────────┐         ┌──────────────┐
                           │ Master host             │◄────────┤ Swarm agent  │
                           │ ┌──────┐ ┌──────┐       │  mTLS   │ (remote host)│
                           │ │ API  │ │Workers│      │  6514   └──────────────┘
                           │ │ Web  │ │ + Bus │      │
                           │ └──▲───┘ └──┬───┘       │
                           │    │        │            │
                           │ ┌──┴───┐ ┌──▼───┐       │
                           │ │ DB   │ │ Logs │       │
                           │ └──────┘ └──────┘       │
                           └────▲────────────────────┘
                                │ HTTPS + JWT
  ── TRUST BOUNDARY: dashboard user ↔ API ──────────────────────────
                                │
                  ┌─────────────┴───────────┐
                  │ Dashboard user          │
                  │ (viewer / admin role)   │
                  └─────────────────────────┘
```

### Trust boundaries (top-level)

| # | Boundary | Component doc |
|---|----------|---------------|
| 1 | Attacker ↔ Decky (the whole point: attackers cross this by design) | *not yet modeled* |
| 2 | Decky ↔ Master (syslog path) | *not yet modeled* |
| 3 | Swarm agent ↔ Master (mTLS API) | *partially — see* `feedback_mtls_pin_per_host.md` |
| 4 | Dashboard user ↔ API | **[Component 1](#component-1--dashboard-user--api)** ← this doc |
| 5 | Bus client ↔ Bus (local IPC) | *not yet modeled* |
| 6 | Updater daemon ↔ Update source | *not yet modeled* |
| 7 | Federation peer ↔ Federation peer (v2) | *see* `DEVELOPMENT_V2.md` §Federation |

---

## Component 1 — Dashboard user ↔ API

**Status:** first component modeled; sets the template for the rest.
**Scope:** everything the React dashboard sends to `/api/v1/*` and
everything the API sends back. Out of scope for this component:
master↔agent API, service-to-service calls within the master.

### DFD

```
                    ┌────────────────────────────────┐
                    │ Dashboard user (browser)       │
                    │  React SPA, JWT in memory       │
                    └─────────────┬──────────────────┘
                                  │
                                  │ HTTPS (TLS to reverse proxy)
                                  │ JWT in Authorization header
                                  │ (exception: SSE uses ?token=<jwt>)
                                  │
  ══ TRUST BOUNDARY ═══════════════│═══════════════════════════════════
                                  │
                    ┌─────────────▼──────────────────┐
                    │ FastAPI app (decnet api)       │
                    │  ┌─────────────────────────┐   │
                    │  │ Auth middleware / JWT   │   │
                    │  │ decode + role extract   │   │
                    │  └───────────┬─────────────┘   │
                    │              │ authenticated   │
                    │  ┌───────────▼─────────────┐   │
                    │  │ Dependencies:           │   │
                    │  │  require_viewer         │   │
                    │  │  require_admin          │   │
                    │  │  require_master_mode    │   │
                    │  └───────────┬─────────────┘   │
                    │              │ authorized      │
                    │  ┌───────────▼─────────────┐   │
                    │  │ Route handler           │   │
                    │  │  → repo (SQLModel)      │   │
                    │  │  → bus publish          │   │
                    │  │  → artifact filesystem  │   │
                    │  └─────────────────────────┘   │
                    └────────────────────────────────┘
```

### Sub-flows in scope

| ID | Flow | Examples |
|----|------|----------|
| F1 | Authn | `POST /auth/login`, JWT issuance, `POST /auth/change-password` |
| F2 | Authz | every route's `require_*` decoration; role checks at dependency layer |
| F3 | Data reads (non-query) | `GET /attackers/{uuid}`, `GET /deckies/{name}`, `GET /health` |
| F4 | Queries (user-filtered) | `GET /logs?service=&severity=&q=`, `GET /attackers?…`, `GET /bounties?…`, `GET /attackers/{uuid}/commands?service=&limit=&offset=` |
| F5 | Mutations | `PATCH /deckies/*`, `POST /config/*`, `POST /users`, `DELETE /users/{u}`, `POST /topologies`, `POST /topologies/{id}/mutations` |
| F6 | Streaming / SSE | `GET /stream/events?token=`, `GET /topologies/{id}/events?token=` |
| F7 | Downloads | `GET /artifacts/{decky}/{stored_as}?service=` (ssh / smtp), `GET /attackers/{uuid}/mail` |

### STRIDE enumeration

Each sub-flow below gets its own table. Status codes:
**M** = mitigated · **A** = accepted · **T** = transferred ·
**?** = needs verification · **X** = out of scope.

#### F1 — Authn

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | Credential stuffing / brute force on `/auth/login` | M | slowapi two-bucket rate limit at `decnet/web/router/auth/api_login.py`: 10/5min per-IP AND 10/5min per-username, tripping either → 429. In-memory storage (`decnet/web/limiter.py`). |
| S | JWT forgery with weak/leaked secret | M | `DECNET_JWT_SECRET` required, 32+ chars; signing verified on every request. Operator deployment responsibility to rotate on suspected leak. |
| S | Stolen JWT replayed from attacker's browser | A | JWT TTL is short; no server-side session revocation pre-v1. Accepted: revisit if customer demands immediate-revocation. |
| T | Password hash tampering in DB | T | DB integrity is OS/filesystem scope. See boundary #2 for syslog-path tampering. |
| R | User denies having performed an action | M | Every mutation logged with actor UUID; audit trail lives in `logs` table. |
| I | Password reflected in login response on failure | M | Single uniform 401 for user-not-found and bad-password at `api_login.py`. No user-existence oracle. |
| I | JWT secret leaked via error message / stack trace | M | Generic `@app.exception_handler(Exception)` at `decnet/web/api.py` returns opaque `{detail, error_id}` on uncaught exceptions; traceback is logged server-side only. Dev-mode (`DECNET_DEVELOPER=True`) includes traceback in body for debugging. |
| D | Bcrypt-cost DoS via long password submission | M | Pydantic `max_length=72` on all password fields in `decnet/web/db/models/auth.py` (matches bcrypt's internal truncation limit). |
| E | `role=None` bypass (historical bug) | M | See memory `project_rbac_null_role.md`; fixed via centralized RBAC that treats `None` as unauthenticated. |

#### F2 — Authz

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | Forged role claim in JWT | M | Role read from DB by UUID on each authz, not trusted from token. (Verify — see `project_rbac_null_role.md`.) |
| T | Client-side role flag tampering | M | Server-side gating required; client-side hide-only is UI polish. See `feedback_serverside_ui.md`. |
| R | Admin denies granting a role | M | `update_user_role` calls logged. |
| I | Route missing `require_*` accidentally exposes admin data to viewer | M | 401 half covered by `tests/api/test_schemathesis.py::test_auth_enforcement` (schemathesis + `ignored_auth` check on every operation). 403 half covered by `tests/api/test_rbac_contract.py`, which introspects every `APIRoute.dependant` at collection time, classifies each as admin/viewer/open via identity-match against the `require_admin`/`require_viewer` singletons, and asserts a viewer JWT receives 403 on admin routes and non-401/403 on viewer routes. SSE routes are skipped (covered separately under F6). |
| D | n/a (authz is a check, not a bottleneck) | — | |
| E | Viewer crafts path traversal in URL to hit admin route | M | FastAPI path matching is exact; no dynamic include. |
| E | Master-only CLI command reachable in agent mode | M | `MASTER_ONLY_COMMANDS` gating at CLI registration + `_require_master_mode()` guard in handler. |

#### F3 — Data reads (non-query)

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | (same as F2) | — | |
| T | Response body tampered in transit | T | TLS to reverse proxy is operator-deployment scope. |
| R | n/a (read-only) | — | |
| I | Non-existent resource returns different status than forbidden | M | Attacker-not-found returns 404 after authz passes, consistent with other handlers. |
| I | Sensitive fields bleed into viewer response (e.g. attacker PII) | **?** | Verify: field allow-listing on attacker serializer for viewer role. |
| D | Heavy single-resource fetch (rare) | A | Unbounded fetch on a single row is bounded by row size. Accepted. |
| E | n/a (no privilege change) | — | |

#### F4 — Queries (densest threat surface)

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | (inherited from authn/authz) | — | |
| T | SQL injection via filter params | M | SQLModel uses parameterized queries exclusively; no string-concatenation SQL in repo. Verify on each new query endpoint. |
| T | ORM expression injection (e.g. sort-by-arbitrary-column) | M | Only one client-supplied sort key exists across the API: `sort_by` on `/attackers` (`api_get_attackers.py:59`), which is `Query(..., pattern="^(recent\|active\|traversals)$")`. The repo dispatch in `sqlmodel_repo.py:829-832` uses a dict lookup, not raw `order_by(getattr(...))`. No other route accepts a client-supplied column name. |
| R | Query log does not record who queried what | A | Pre-v1: query audit log out of scope. Revisit if customer demands query-level audit. |
| I | Filter-bypass exfiltration: viewer filters return admin-visible rows | **?** | Verify: repo methods take the caller's role and scope results, OR routes pre-filter, OR data is viewer-safe by schema. Currently assumed "viewer-safe by schema" — worth asserting in a test. |
| I | Timing side channel reveals existence of filtered-out rows | A | Micro-timing attacks on SQLite not a realistic threat for this workload. Accepted. |
| I | Error message (422 / 500) leaks column names or SQL fragments | M | FastAPI 422 is schema-shaped; 500 handler must not return tracebacks in prod. Verify handler config. |
| I | Schema enumeration via schemathesis-style fuzzing | A | Schemathesis contract tests document 400/422 shape; an attacker learning the schema gains nothing beyond the public OpenAPI spec. See `feedback_schemathesis_400.md`. |
| D | Unbounded result set via missing `limit` | M | Every query endpoint declares `limit: int = Query(..., le=N)` at the FastAPI layer — `/logs`, `/attackers`, `/bounties`, `/attacker-commands`, `/topologies/{id}` (`le=1000`), `/topologies` (`le=500`), `/transcripts` (`le=5000`). Cap enforced at pydantic validation, before the handler runs. |
| D | Deep-pagination scan via large `offset` | M | Every `offset` param is `Query(0, ge=0, le=2147483647)` (INT32 max). At that scale SQLite returns empty immediately once rows exhaust; the point is to keep callers within a range the indexer can skip cheaply. `api_get_transcript.py:147` and `api_list_topologies.py:29` brought in line 2026-04-24. |
| D | Expensive `LIKE '%foo%'` on non-indexed column | A | See DA-09. `/logs?search=` LIKE-scans four columns on the unbounded logs table; `/attackers?search=` LIKE-scans `attacker.ip`. Both routes are admin-gated. Cost-to-caller is bounded by `limit ≤ 1000` and by operator-level reverse-proxy rate limiting (see DA-04). Performance upgrade to FTS5 is tracked separately; within the current admin-trust model the cost is acceptable. |
| D | Repeated expensive queries from single user | A | Per-user rate limiting is out of scope pre-v1. Operator-deployment mitigation: reverse-proxy rate limit. |
| E | Filter params allow reading across tenants (future multi-tenant) | X | Multi-tenant is not in the v1 model; revisit when tenants exist. |

#### F5 — Mutations

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | Forged mutation from non-authenticated client | M | `require_admin` on all mutations; JWT enforced. |
| T | Replay of a captured mutation request | A | No nonce/idempotency-key pre-v1. Accepted: admin role already has full mutation power; replay gains nothing a fresh request couldn't. Revisit if multi-admin audit becomes a requirement. |
| T | Concurrent-write race corrupting state | **?** | Verify: SQLModel session scoping + DB-level constraints cover the likely races (user creation, topology CRUD). |
| R | Admin denies having mutated | M | Actor UUID + timestamp logged on every mutation. |
| I | Mutation response returns internal state not meant for client | M | Every mutation route that returns a dict-shaped body now pins `response_model=...` at the decorator: `MessageResponse` for `{"message": ...}` envelopes, purpose-built models (`DeployResponse`, `PurgeResponse`, `ReapReportResponse`, `UserResponse`) for richer shapes. FastAPI strips undocumented extra fields at serialization time, so a handler that accidentally returned a full user row (including `password_hash`) would only ship declared fields. `Response`/`ORJSONResponse` routes bypass response_model intentionally and are audited individually. |
| D | Malformed body triggers expensive validation / oversized payload | M | FastAPI enforces content-length at ASGI layer; Pydantic short-circuits on type mismatch. |
| D | Destructive mutation storm (e.g. delete-all-users) | A | Admin role is trusted; protecting admins from themselves is out of scope. |
| E | Mutation bypasses role check via missing `require_admin` | M | `tests/api/test_rbac_contract.py::test_admin_route_rejects_viewer` parametrizes every route classified admin by FastAPI-dependency introspection (identity-match on the `require_admin` closure) and asserts viewer JWT → 403. A missing `require_admin` would reclassify the route away from "admin" and break the viewer route's non-403 assertion, so the check is bidirectional. |

#### F6 — Streaming / SSE

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | Token-in-query-string logged by reverse proxy / browser history | A | SSE cannot use Authorization header; `?token=<jwt>` is the standard workaround. Mitigation: short JWT TTL, operator must scrub access logs if compliance requires. Document explicitly. |
| T | Injected events into the stream from another client | M | Events are repo→bus→SSE one-way; no client-to-client. |
| R | User denies having observed events | X | Passive read; non-repudiation n/a. |
| I | SSE forwards events the user's role shouldn't see | M | Both SSE streams are viewer-safe by construction. `/stream` (`api_stream_events.py:59`) emits `logs`/`stats`/`histogram` — same data reachable via viewer-gated REST (`/logs`, `/stats`). `/topologies/{id}/events` (`api_events.py:59`) emits `snapshot`/`status`/`mutation.{state}` — mutation metadata is already viewer-readable via `/topologies/{id}/mutations`; status is viewer-readable via `/topologies/{id}`. Both handlers carry a docstring invariant: adding a new event family requires a threat-model review. Currently no admin-only field is emitted on either path. |
| D | Connection exhaustion (hold many SSE connections open) | M | Per-user cap enforced via `decnet/web/sse_limits.py::sse_connection_slot`, wired into both SSE generators as their first `async with`. Default cap 5 per user UUID, overridable via `DECNET_SSE_MAX_PER_USER`. Exceeding the cap returns `429 Too Many Requests` before any stream data is yielded. Tested at `tests/api/test_sse_limits.py`. |
| E | n/a | — | |

#### F7 — Downloads

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | (inherited) | — | |
| T | Path-traversal via `{decky}` or `{stored_as}` to read arbitrary files | M | Pattern-validated at FastAPI layer (`{service}` is `^[a-z]{1,16}$`; artifact names are UUID-shaped) AND containment-checked in `_resolve_artifact_path` at `decnet/web/router/artifacts/api_get_artifact.py:48-64` (both root and candidate are `.resolve()`d, then `root in candidate.parents` is asserted — defence-in-depth against symlinks). |
| R | Admin denies having downloaded | M | Download endpoint emits an access log entry. |
| I | Viewer accesses attacker-controlled bytes | M | Admin-gated (`require_admin`). Rationale: artifacts are phishing kits / malware droppers / attacker-controlled content — see `api_get_attacker_mail.py` docstring. |
| I | MIME sniffing / content-type confusion executes attacker payload in browser | M | `FileResponse` at `decnet/web/router/artifacts/api_get_artifact.py:87` sets both `Content-Disposition: attachment; filename="..."` and `X-Content-Type-Options: nosniff` explicitly (not relying on Starlette's default, which only emits `attachment` for non-ASCII filenames). |
| D | Gigabyte-sized artifact download ties up workers | M | SMTP body cap is 10 MB (EHLO SIZE enforcement); SSH artifact sizes bounded by disk quota. |
| E | Downloaded artifact escapes the browser sandbox | T | Browser security boundary is transferred to the browser vendor and operator's endpoint protection. |

### Accepted risks (Dashboard ↔ API)

Consolidated for easy reference:

| ID | Threat | Why accepted | Revisit when |
|----|--------|--------------|--------------|
| DA-01 | Stolen JWT replayable until TTL expiry | Server-side revocation list is infra cost disproportionate to v1 threat model | Customer demands immediate revocation, OR swarm-scale deployment where JWT theft blast radius grows |
| DA-02 | Query-level audit log absent | Admin-mutation audit is sufficient pre-v1 | Regulated-industry customer engagement |
| DA-03 | Query-filter timing side channel | SQLite + single-tenant; impact is negligible | Multi-tenant support lands |
| DA-04 | Per-user query rate limiting absent | Trusted operator deployment; reverse-proxy rate limit is the operator's responsibility | SaaS / multi-tenant hosting model |
| DA-05 | Mutation replay within admin session | Replay grants no privilege a fresh request wouldn't | Multi-admin audit requirement |
| DA-06 | Destructive admin mutations not protected against the admin | Trusted-admin assumption; protecting root from root is out of scope | Multi-admin RBAC with mutual-approval workflows |
| DA-07 | SSE token in query string | No alternative in the SSE spec; operator must control access-log handling | Move to WebSocket with in-band auth |
| DA-08 | Reverse-proxy deployments collapse per-IP rate-limit bucket to one shared bucket | `X-Forwarded-For` is spoofable by any client; trusting it defeats the rate limit. Operators behind a proxy get coarser granularity but no spoofing lane. | Verified-proxy config lands (allow-list of proxy IPs whose `X-Forwarded-For` we trust) |
| DA-09 | Admin-initiated `LIKE '%q%'` scan on `/logs` or `/attackers` ties up a worker for the duration of the scan on a large dataset | Both routes are admin-gated; the admin role already carries DA-06 (protecting admins from themselves is out of scope). `limit ≤ 1000` caps the result page size, and per-user rate-limiting is operator-scope per DA-04. FTS5 is a performance upgrade, not a security change, under the current trust model. | Logs table growth causes operator-observable latency on the LIKE path, OR trust model changes (multi-tenant / SaaS / untrusted-admin delegation) |

### Needs-verification checklist (Dashboard ↔ API)

Drop-in TODO list — each entry resolves to either "mitigated, link to
code" or "accepted, add to table above."

- [x] ~~Per-IP / per-user rate limit on `/auth/login`.~~ Shipped — see F1/S row.
- [x] ~~Uniform "invalid credentials" on login failure (no user-existence oracle).~~ Verified — see F1/I row.
- [x] ~~Production error handler suppresses tracebacks and internal details.~~ Shipped — generic `@app.exception_handler(Exception)` in `decnet/web/api.py`; opaque `{detail, error_id}` in prod, traceback only under `DECNET_DEVELOPER=True`.
- [x] ~~`detail=str(e)` / `detail=f"…{e}"` sites in `decnet/web/router/fleet/api_deploy_deckies.py:41,67,83,155`.~~ Audited 2026-04-24: L41 + L83 are deliberate `ValueError` messages from `load_ini_from_string` / `build_deckies_from_ini` (user-authored INI validator feedback, not internal state); L67/73 wraps `detect_subnet`'s `RuntimeError` with a remediation hint (`"Add a [general] section with interface=, net=, and gw="`); L155 aggregates structured `DispatchResult.detail` fields from swarm workers, not raw exceptions. All four sites are admin-gated. No sanitization needed.
- [x] ~~Password length clamp before bcrypt.~~ Verified — Pydantic `max_length=72`.
- [x] ~~Contract test asserting every protected route returns 401 unauthenticated and 403 for under-roled.~~ 401 half: `tests/api/test_schemathesis.py::test_auth_enforcement` (schemathesis + `ignored_auth`). 403 half: `tests/api/test_rbac_contract.py` (server-side dependency introspection + viewer JWT per route). Role hints deliberately kept out of the OpenAPI spec — classification stays server-side.
- [ ] Field allow-list on viewer responses for attacker / user / bounty serializers.
- [x] ~~Sort/filter query keys are allow-listed, not passed through raw.~~ Only one client-supplied sort key in the API (`sort_by` on `/attackers`), pattern-validated at `api_get_attackers.py:59`; repo dispatch is dict-lookup. No other route accepts a column name.
- [ ] Role-scoped repo methods OR per-route pre-filter for viewer queries (pick one, document it).
- [x] ~~Every query endpoint has a server-side hard cap independent of `limit`.~~ All 7 query endpoints declare `Query(..., le=N)` at the FastAPI layer; enforced pre-handler.
- [x] ~~`offset` is capped OR pagination is cursor-based OR deep-offset is cheap.~~ Every `offset` now uses `le=2147483647` (`api_list_topologies.py:29` and `api_get_transcript.py:147` brought in line 2026-04-24; others already capped).
- [x] ~~Free-text `q` parameters hit an indexed/FTS5 column, never a full-table `LIKE` scan.~~ Moved to accepted risk **DA-09** — admin-only surface, `limit` capped, operator rate-limit applies. Revisit if logs-table LIKE latency becomes operator-observable OR if the trust model changes (multi-tenant / SaaS).
- [x] ~~Per-route response_model shape audit on mutations.~~ Every dict-returning mutation now declares `response_model=...`. `MessageResponse` covers the 8 `{"message": ...}` envelopes; `DeployResponse`/`PurgeResponse`/`ReapReportResponse`/`UserResponse` cover the richer shapes. 204-No-Content routes and manual `Response`/`ORJSONResponse` routes are explicitly scoped out (no body to validate).
- [x] ~~Contract test asserting every mutation route returns 403 for viewer.~~ Covered by `test_rbac_contract.py` (same test also covers read routes — classification is by dependency, not HTTP verb).
- [x] ~~SSE handler applies per-connection role filter before forwarding events.~~ Viewer-safe by construction on both streams — every event type on `/stream` and `/topologies/{id}/events` wraps data already reachable via viewer-gated REST. Handler docstrings now carry the invariant: new event families require a threat-model review.
- [x] ~~Per-user concurrent SSE connection cap.~~ `decnet/web/sse_limits.py::sse_connection_slot` gates both SSE generators; default 5 per user UUID, `DECNET_SSE_MAX_PER_USER` override, 429 on overflow. Tests at `tests/api/test_sse_limits.py`.
- [x] ~~Artifact download sets `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`.~~ Shipped — explicit headers on `FileResponse` in `api_get_artifact.py`; asserted in `tests/api/artifacts/test_get_artifact.py::test_content_disposition_is_attachment`.
- [x] ~~Artifact path resolution asserts the resolved path is under the artifacts root (canonicalize + prefix check).~~ Verified — `_resolve_artifact_path` at `api_get_artifact.py:48-64` resolves both sides and asserts `root in candidate.parents`.

### Out of scope (this component)

- TLS termination correctness (operator's reverse proxy).
- Browser-side XSS originating from user-controlled content rendered in the dashboard (that's a frontend threat model, separate document when we write one).
- Physical access to the master host.
- Supply-chain compromise of FastAPI / SQLModel / dependencies (upstream / OS scope).
- Denial of service at the network layer (operator deployment).

---

## Master out-of-scope register

These threats are excluded from the DECNET threat model entirely,
regardless of component:

- **Physical attacker at the master or agent console.** Disk
  encryption, console access, BMC/iLO security is the operator's
  responsibility.
- **Nation-state zero-days in Linux kernel / systemd / Docker.**
- **Upstream supply-chain compromise of Python packages or base images**
  beyond what `pip-audit` + the pre-commit hook catches.
- **Side channels at the hardware level** (Spectre, Rowhammer, etc.).
- **Attacks on the operator's own endpoint** (laptop used to access the
  dashboard).

## Master accepted-risks register

*(Consolidates per-component accepted entries as they are added.)*

| Component | ID | Summary |
|-----------|----|---------|
| Dashboard↔API | DA-01..DA-09 | See component section. |
| DECNET↔Webhook destination | WH-01..WH-03 | See component section. |

---

## Component 2 — DECNET ↔ External webhook destination

**Status:** modeled alongside the webhook MVP (2026-04-24).
**Scope:** outbound HTTP POSTs from the `decnet webhook` worker to an
operator-configured URL (typically Shuffle / TheHive / Wazuh / n8n).
In scope: the data crossing the master→receiver boundary, the signing
& secret storage, and the failure behavior of the egress path. Out of
scope: the receiver's own security posture, anything downstream of
the receiver (Shuffle→Slack, TheHive→Cortex, …).

### DFD

```
  Master host
  ┌─────────────────────────────────────┐
  │ ┌────────────────────┐              │
  │ │ WebhookSubscription│   (DB row)   │
  │ │  url, secret,      │              │
  │ │  topic_patterns    │              │
  │ └─────────┬──────────┘              │
  │           │ read                    │
  │ ┌─────────▼────────┐   bus events   │
  │ │ decnet webhook   │◄──── bus ◄─── other workers (attacker.*, decky.*, system.*)
  │ │ worker           │                │
  │ └─────────┬────────┘                │
  │           │ HMAC-signed POST        │
  └───────────│─────────────────────────┘
              │
  ══ TRUST BOUNDARY ═══════════════════════════════════
              │
              ▼
          External receiver (Shuffle / TheHive / Wazuh / n8n / ...)
```

### STRIDE enumeration

| Cat | Threat | Status | Notes |
|-----|--------|--------|-------|
| S | Receiver accepts a forged event impersonating DECNET | M | Every POST carries `X-DECNET-Signature: sha256=<hex>` computed with HMAC-SHA256 over the canonical body (orjson with sorted keys); per-subscription secret. Receiver recomputes + compares. See `decnet/webhook/client.py::sign`. |
| S | Attacker controls a webhook URL the admin added and forges callbacks back to DECNET | X | DECNET does not accept inbound webhook POSTs; only egress. Receiver→DECNET is not a surface in this component. |
| T | Payload tampering in transit | T / M | TLS termination is the operator's responsibility (same stance as Dashboard↔API). If the URL is `http://` on a hostile network, the HMAC still detects tampering — a recomputed signature would fail on any altered byte. Operators MUST use `https://`; the router does not enforce this pre-v1 (see WH-01). |
| T | Secret leak lets attackers forge events in-band | A | Secret rotation is a manual PATCH. In-flight window where a rotated secret is observed by both old + new verifiers is the operator's coordination problem. Encrypt-at-rest on the DB column is deferred — see DEBT-037 §7. |
| R | DECNET denies having sent an event | M | `last_success_at` + `last_failure_at` stamps on the row; structured log per delivery with `event_id`. No persisted per-event audit log pre-v1 — see DEBT-037 §3. |
| I | Secret leaks via API GET/LIST response | M | `WebhookResponse` deliberately omits the `secret` field. `WebhookCreateResponse` carries the secret exactly once on create for copy-out. PATCH-to-rotate, no read-back. |
| I | Webhook URL + secret leak via DB dump | A | Plaintext at-rest on SQLite/MySQL. Same trust assumption as the JWT secret (which is env-sourced, not DB-stored). See WH-01 and DEBT-037 §7. |
| I | Attacker-controlled event content reaches receiver | T | Event payloads pass through DECNET untransformed — the receiver must sanitize before rendering (e.g. XSS if Shuffle pipes to a browser-facing Slack block without escaping). Out of scope for the DECNET side. Document in operator docs. |
| D | Slow / unreachable receiver ties up egress | M / A | Bounded concurrency (`Semaphore(10)`), per-delivery timeout (10s), and bounded retry (3 attempts, `[1,2,4]` × jitter) keep one slow destination from starving others. Half-dead receivers still waste retry budget — see WH-02. Circuit breaker deferred to DEBT-037 §1. |
| D | Huge payload floods receiver | A | Payload shape is whatever the bus event carries; no per-destination batching / coalescing. On high-volume topics this is a known concern — see DEBT-037 §4 for post-MVP batch delivery. |
| E | Viewer role manipulates webhook config | M | All CRUD routes under `/api/v1/webhooks` are `Depends(require_admin)`. Verified by `tests/api/test_rbac_contract.py` (every admin-classified route asserts viewer → 403). |
| E | Admin adds a URL pointing at an internal-only DECNET service (SSRF-style) | A | Admin role is trusted; protecting admin from self-inflicted SSRF is out of scope under the current trust model. Revisit if we ever delegate subscription CRUD to a less-trusted role. |

### Accepted risks (DECNET↔Webhook)

| ID | Threat | Why accepted | Revisit when |
|----|--------|--------------|--------------|
| WH-01 | Webhook secret + URL stored plaintext in the DB | Matches the existing pre-v1 posture (JWT secret is env-sourced; there's no operator expectation that DB-at-rest is encrypted). Encrypting one column in isolation invents a KEK lifecycle we don't have. | Comprehensive DB-at-rest encryption lands, OR regulated-industry customer engagement. Tracked in DEBT-037 §7. |
| WH-02 | Half-dead receiver wastes the full retry budget (1+2+4 ≈ 7s with jitter) per delivery before the worker gives up | Admin role is trusted; this is operator-observable via `consecutive_failures` on the subscription row. A sticky-failure receiver disabled itself via operator action is fine pre-v1. | Circuit breaker lands (DEBT-037 §1) — auto-disable after N consecutive failures, require admin re-enable. |
| WH-03 | Admin configures an `http://` webhook URL; event body (incl. payload fields) travels plaintext on the wire | Operator-trust posture (same rationale as DA-06: protecting admin from self is out of scope). HMAC signature still detects tampering regardless of transport — only *read* confidentiality is lost. The API surfaces a non-blocking warning in `WebhookResponse.warnings` so the operator is informed on every GET/CREATE, and test/dev environments without TLS remain usable. | Multi-admin delegation lands, OR a regulated-industry customer engagement, OR an operator ticket asks for a `DECNET_WEBHOOK_REQUIRE_HTTPS=true` enforcement knob. |

### Needs-verification checklist (DECNET↔Webhook)

- [x] HMAC-SHA256 signing over canonical (orjson sorted-keys) body — verified by `tests/webhook/test_client.py::test_deliver_receiver_can_verify_signature`.
- [x] Secret never leaks via GET/LIST response — `tests/api/webhooks/test_crud.py::test_list_strips_secret` + `::test_get_single_strips_secret`.
- [x] Admin-only CRUD — inherited invariant from `test_rbac_contract.py`; new webhook routes auto-classified as admin.
- [x] 4xx no-retry, 5xx/429/network retry — `tests/webhook/test_client.py::test_deliver_no_retry_on_4xx` + retry tests.
- [x] Bounded concurrency + timeout per delivery — `Semaphore(10)` + 10s httpx timeout in `worker.py`.
- [ ] Secret-field omission on the OpenAPI schema (not just the response body). Verify that `/openapi.json` shows `WebhookResponse` without `secret` so SDK consumers don't accidentally deserialize into a shape that expects it.
- [x] ~~Reject `http://` URLs at admin time.~~ Resolved as **WH-03 accepted risk** — operator-trust posture, we warn rather than reject. `WebhookResponse.warnings` surfaces an `insecure_url` advisory on every GET/CREATE when the URL starts with `http://`. Tested at `tests/api/webhooks/test_crud.py::test_http_url_warns_but_accepts`.

### Out of scope (this component)

- The receiver's auth, storage, or downstream routing.
- Post-MVP hardening (circuit breaker, dead-letter, batch, templates, at-rest encryption) — all tracked in DEBT-037.
- Frontend UI for subscription CRUD — a separate commit series.

---

## Components not yet modeled

In priority order:

1. Decky ↔ Master (syslog path) — data-integrity critical.
2. Swarm agent ↔ Master (mTLS) — existing pinning; document it.
3. Federation peer ↔ Peer — see `DEVELOPMENT_V2.md` §Federation for
   analysis; migrate into this doc when v2 lands.
4. Bus client ↔ Bus — local IPC, narrow surface.
5. Updater daemon ↔ Update source.
6. Decky itself (attacker-facing surface) — largest S/T/E surface; do
   this once the internal boundaries are modeled.

## Change log

| Date | Change | Author |
|------|--------|--------|
| 2026-04-23 | Initial scaffold. System context + Dashboard↔API as first worked component. | ANTI |
| 2026-04-23 | F1 Authn: 3 threats moved from **?** to **M** (rate limit shipped; uniform 401 verified; bcrypt length clamp verified). Added DA-08 accepted risk: reverse-proxy per-IP bucket collapse. | ANTI |
| 2026-04-23 | F1/I "traceback / stack trace leakage" moved from **?** to **M** via generic Exception handler with `error_id` correlation. Added follow-up checklist entry for `detail=str(e)` sites in fleet deploy router. | ANTI |
| 2026-04-24 | F7: "MIME sniffing" moved from **?** to **M** (explicit `Content-Disposition`/`nosniff` headers + test). F7: "path-traversal" row reworded to point at the existing `_resolve_artifact_path` containment check. Fleet-deploy `detail=str(e)` audit resolved — all four sites documented as deliberate, admin-gated, no sanitization needed. | ANTI |
| 2026-04-24 | F2/I + F5/E moved from **?** to **M** via new `tests/api/test_rbac_contract.py` — classifies every APIRoute by FastAPI-dependency introspection and asserts viewer JWT → 403 on admin routes, non-401/403 on viewer routes. Role hints deliberately omitted from OpenAPI spec. SSE routes skipped (F6 scope). | ANTI |
| 2026-04-24 | F4/T (ORM sort injection), F4/D (unbounded `limit`), F4/D (deep `offset`) all moved from **?** to **M**. Limit caps were already universal; sort is pattern-validated on the only surface that exposes it; added `le=2147483647` to the two offset params that were unbounded (`api_list_topologies.py`, `api_get_transcript.py`). | ANTI |
| 2026-04-24 | F5/I moved from **?** to **M** via `response_model=...` on every dict-returning mutation (`MessageResponse` + purpose-built models). F4/D "expensive `LIKE`" moved from **?** to **A** under new accepted risk DA-09 — admin-only surface, operator-scope rate limiting, `limit` cap. FTS5 kept as a performance TODO, not a security blocker. | ANTI |
| 2026-04-24 | F6/I and F6/D both moved from **?** to **M**. F6/I: documented the viewer-safe-by-construction invariant for both SSE streams (every emitted event type wraps data already viewer-readable via REST). F6/D: added `decnet/web/sse_limits.py::sse_connection_slot` — per-user counter + async lock + 429 on overflow, wired into both SSE generators. `DECNET_SSE_MAX_PER_USER` env knob, default 5. | ANTI |
| 2026-04-24 | Component 2 added — DECNET↔External webhook destination. Covers the new `decnet webhook` worker + `/api/v1/webhooks` admin CRUD. HMAC-SHA256 signing, 4xx no-retry + 5xx/429 retry with jittered backoff, admin-only CRUD, secret never leaks post-create. Two accepted risks registered (WH-01 secret at rest, WH-02 half-dead-receiver retry waste) paired with DEBT-037 pointers. | ANTI |
| 2026-04-24 | WH-03 accepted risk added — `http://` webhook URLs are allowed (operator-trust posture) but surface an `insecure_url` advisory in `WebhookResponse.warnings`. Checklist item "reject http://" resolved as "warn, not reject" per explicit operator decision. | ANTI |
