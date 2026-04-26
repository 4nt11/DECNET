# TODO — credential reuse + vectorstore (handoff)

This document hands off in-progress work on the **credential reuse
patterns** task from `development/DEVELOPMENT.md` (under *Service-Level
Behavioral Profiling*) plus the **`decnet/vectorstore/`** scaffolding
that prepares the substrate for a future statistical re-identification
engine over behavioral fingerprints. See
`/home/anti/.claude/plans/ah-excellent-alright-claude-vivid-thimble.md`
for the full approved plan and motivation.

## Done in the previous session

Foundation is shipped + tested (26 new tests passing, no regressions):

- **Schema** — `decnet/web/db/models/logs.py`
  - `Credential.attacker_uuid: Optional[str]` FK to `attackers.uuid`,
    nullable. Backfilled by the profiler post-write.
  - `CredentialReuse` table (UUID PK; JSON list columns for
    `attacker_uuids`, `attacker_ips`, `deckies`, `services`;
    `target_count`, `attempt_count`, `confidence` reserved for future
    fuzzy matching). Unique key: `(secret_sha256, secret_kind,
    principal_key)`.
  - `CredentialReuseResponse` Pydantic DTO.
- **Repo** — `decnet/web/db/sqlmodel_repo.py` + `repository.py`
  - `upsert_credential_reuse(...)`,
    `list_credential_reuses(limit, offset, min_target_count, secret_kind)`,
    `get_credential_reuse_by_id(id)`,
    `update_credential_attacker_uuid(attacker_ip, attacker_uuid) -> int`.
  - **Rename**: pre-existing `get_credential_reuse(secret_sha256)` →
    `get_credential_attempts_for_secret(secret_sha256)`. All callers
    updated.
- **Bus topics** — `decnet/bus/topics.py`
  - `CREDENTIAL_CAPTURED = "captured"` (one per Credential upsert).
  - `CREDENTIAL_REUSE_DETECTED = "reuse.detected"` (correlator emits
    on insert/grow).
  - `credential(event_type)` builder.
- **Vectorstore** — `decnet/vectorstore/` (NEW; flat layout mirroring
  `decnet/bus/`)
  - `base.py` — `BaseVectorStore` ABC,  `VectorRecord`, `Neighbor`,
    `VECTORSTORE_SCHEMA_VERSION`. Methods: `initialize`, `close`,
    `health`, `insert`, `get`, `delete`, `knn`. Keyed by `(kind, id)`.
  - `fake.py` — `FakeVectorStore` (in-memory, brute-force L2 KNN) +
    `NullVectorStore` (no-op when `DECNET_VECTORSTORE_ENABLED=false`).
  - `sqlite_vec.py` — `SqliteVecVectorStore`; lazy-loads the
    `sqlite_vec` extension; one `vec0` virtual table per `kind` so
    new feature families don't require schema migration. Per-kind
    dim is locked on first insert.
  - `factory.py` — `get_vectorstore()` env-driven dispatch
    (`DECNET_VECTORSTORE_TYPE` ∈ {sqlite_vec, fake};
    `DECNET_VECTORSTORE_ENABLED`; `DECNET_VECTORSTORE_PATH`). On
    missing `sqlite_vec` extension: logs a warning and returns
    `FakeVectorStore` so workers don't crash.
- **Tests**
  - `tests/db/test_credential_reuse.py` — 11 tests (upsert idempotency,
    list filters/pagination, FK backfill semantics, null-principal
    uniqueness, JSON-list merging).
  - `tests/vectorstore/test_factory.py` (6) +
    `tests/vectorstore/test_fake.py` (9) — factory dispatch + fallback,
    round-trip, dim-mismatch raises, KNN ordering, NullStore no-op.
  - Updated `tests/db/test_base_repo.py` and
    `tests/db/test_credentials.py` for the rename.

## Not yet done — what the next agent should pick up

Tasks below are roughly in dependency order. Backend first, dashboard
last (it's the largest unknown and benefits from a fresh context).

### 1. Profiler backfill of `Credential.attacker_uuid`

Smallest task; do this first to validate the FK column end-to-end.

- File: `decnet/profiler/` — find the spot where the profiler
  mints/updates an `Attacker` row from observed events. There's
  likely an `upsert_attacker(...)` call that produces the `(ip, uuid)`
  pair.
- Add immediately after a successful upsert:
  ```python
  await repo.update_credential_attacker_uuid(ip, uuid)
  ```
- Test in `tests/profiler/` (whatever the existing test file is) that
  after the profiler processes events for an IP, all `Credential`
  rows for that IP have their `attacker_uuid` populated. Use the
  pattern from `tests/db/test_credential_reuse.py::
  test_update_credential_attacker_uuid_backfills_only_nulls`.

### 2. Correlator engine + worker wiring

- File: `decnet/correlation/engine.py` — add
  `correlate_credential_reuse(min_targets: int = 2)` to
  `CorrelationEngine`. Signature suggested in the plan:
  ```sql
  SELECT secret_sha256, secret_kind, principal,
         COUNT(DISTINCT decky_name||':'||service) AS target_count
  FROM credentials
  GROUP BY secret_sha256, secret_kind, principal
  HAVING target_count >= :min_targets
  ```
  For each group, fetch the underlying credential rows and call
  `repo.upsert_credential_reuse(...)` per row. The repo upsert
  recomputes `target_count` from the `credentials` table on each
  update, so you don't need to pass aggregates in.
- On insert/grow (`out["inserted"] is True or out["changed"] is True`),
  publish `bus.publish(topics.credential(topics.CREDENTIAL_REUSE_DETECTED), {...})`
  with payload `{id, secret_kind, target_count, attacker_uuids,
  attacker_ips, deckies, services}`.
- Worker file: `decnet/correlation/main.py` (or wherever
  `CorrelationEngine` is loop-driven). Subscribe to:
  - `attacker.observed` — re-runs reuse pass for that IP.
  - `credential.captured` — re-runs reuse pass for that secret.
  - Heartbeat tick every 60s as a fallback (mirror the mutator's
    bus-wake + slow-tick pattern).
- Where is `credential.captured` emitted? Find the credential ingest
  path — probably `decnet/collector/` or wherever
  `repo.upsert_credential(...)` is called. Add a `bus.publish(
  topics.credential(topics.CREDENTIAL_CAPTURED), {secret_sha256,
  secret_kind, attacker_ip, decky, service})` after a successful
  upsert. Bus is fire-and-forget — don't block on it.
- Tests:
  - `tests/correlation/test_credential_reuse.py` — engine emits the
    right `CredentialReuse` rows from synthetic credentials; bus
    event published exactly once per insert/grow.
  - Use `decnet.bus.fake.FakeBus` in tests; collect published
    events for assertion.

### 3. API routes — `GET /api/v1/credential-reuse`

- File: probably `decnet/web/api/routes/` — see how existing
  credentials routes are organized (recent commit
  `feat(api): GET /credentials endpoint` → `4566146`).
- Endpoints:
  - `GET /api/v1/credential-reuse?limit=50&offset=0&min_target_count=2&secret_kind=plaintext`
    → `CredentialReuseResponse` (already in models).
  - `GET /api/v1/credential-reuse/{id}` → single row dict, 404 if
    missing.
- JWT-gated like all other routes. Use the existing dependency.
- No POST/PUT/PATCH — read-only this release. Per the
  `feedback_schemathesis_400` memory there's no 400 contract to
  document since there's no body parsing.
- Tests: `tests/api/test_credential_reuse_routes.py` — JWT gate,
  pagination, filters, 404 for missing id.

### 4. Dashboard — Credentials Reuse tab + drawer

The big unknown. Next agent should:

1. Survey `decnet/web/dashboard/` (React app) — how the existing
   Credentials view is structured (commit `4ea4b0b feat(web):
   Credentials view + inspector`).
2. Add a "Reuse" tab/filter that lists `CredentialReuse` rows sorted
   by `target_count desc`.
3. Drawer on row-click showing decky×service breakdown,
   `attacker_uuid` list (link to `/attackers/:id`), timeline. Reuse
   the existing drawer pattern (see `feedback_react_stop_propagation_native_delegation`
   memory — backdrop click closes via `target===currentTarget`,
   never `stopPropagation`).
4. On the existing Credentials list, add a "seen on N targets"
   badge when a credential has a corresponding `CredentialReuse`
   row, so the connection is bidirectional.

### 5. DEVELOPMENT.md

Tick `[x] Credential reuse patterns` under *Service-Level Behavioral
Profiling*. Add a one-liner under *Attacker Intelligence Collection*
noting `decnet/vectorstore/` is scaffolded for the future statistical
re-ID engine (no behavioural change yet).

## Architectural decisions worth knowing

These came out of the design conversation that produced the plan; the
next agent should respect them:

- **Classical statistics, not ML**, for attacker re-identification.
  Cosine/Mahalanobis/KS-test over per-kind feature vectors, weighted
  voting, versioned thresholds. Reproducible, explainable, no model
  drift. ML is reserved for a future *advisory* layer behind the
  factory, never primary.
- **Provider factory pattern is mandatory** for any new pluggable
  backend (storage, transport, similarity). Mirror `decnet/web/db/`
  and `decnet/bus/` — never let workers import concrete backends.
- **`kind` discriminator is the extension point** for new feature
  families. Adding `kind="cmd_ngram"` later does not require schema
  changes — the `vec_<kind>` table is created lazily on first insert.
- **`Credential.attacker_uuid` is nullable on write** by design — the
  credential capture path runs before the profiler mints `Attacker`,
  so coupling them would create a chicken-and-egg ordering bug. The
  profiler backfills.
- **`CredentialReuse.confidence` is always 1.0 today** (exact-secret
  match). The column exists so a future fuzzy-credential pass
  (`hunter2` ≈ `hunter22`) can write 0.x rows without schema work.

## Verification checklist for the next agent

After finishing each chunk:

- `pytest tests/<area> --timeout=30 --timeout-method=thread` — must
  be green before moving on.
- Don't run fuzz/bench/live/stress in the dev loop (memory:
  `feedback_skip_heavy_tests`).
- Don't pre-clear with custom bandit/ruff flags (memory:
  `feedback_trust_git_hooks`) — the pre-commit hook is authoritative.
- Commit per task, not batched (memory: `feedback_commit_per_task`).
  Don't add Co-Authored-By to commit messages.

## Open questions to surface to ANTI before tackling §4

- Should the dashboard "Reuse" surface live as a tab on the existing
  Credentials page, or as a sibling page? (The plan said tab, but
  worth confirming once you've seen the code.)
- Pagination size for the reuse list — match the existing Credentials
  view default, or use a smaller page since the rows are wider?
