# BEHAVE Integration — Design

**Status:** pre-implementation. This doc is the spec; code follows.
**Tracks:** DEBT-050 (replaces stale DEBT-036).
**Spec source:** `/home/anti/Tools/BEHAVE` (sibling, never vendored).
**Engine home:** this repo, `decnet/profiler/behave_shell/` (sublibrary inside the existing `profiler` worker — no new daemon).

## Premise

ANTI built BEHAVE — an out-of-tree behavioural-observation framework
with a primitive registry, a registry-validated `Observation`
envelope, a DECNET-bus event adapter, and a five-class calibration
grid (HUMAN / YOU-sim / LW-sim / CLAUDE-FF / CLAUDE-CL). It is the
right substrate for keystroke-dynamics extraction.

The original DEBT-036 plan (hand-rolled `kd_*` columns on
`SessionProfile`) is obsolete. This doc replaces it with a
BEHAVE-aligned ingester that emits registry-validated observations on
the bus and persists them in a single generic table.

**Bright line, lifted from BEHAVE itself:** *BEHAVE emits
observations. It does not conclude.* DECNET is a consumer of
`attacker.observation.*` events; attribution / linkage / verdicts are
out-of-scope for this integration and live in their own (future)
attribution engine.

## Architectural placement

```
/home/anti/Tools/
├── BEHAVE/                                    sibling repo, separate git history
│   ├── core/                                  decnet-behave-core (envelope)
│   ├── BEHAVE-SHELL/                          decnet-behave-shell (registry + adapter)
│   └── prototype_extractors/shell/            extract.py — JSONL → Observation stream
│
└── DECNET/                                    THIS repo
    ├── pyproject.toml                         pins decnet-behave-{core,shell}
    ├── decnet/profiler/                       EXISTING worker — gains a sublibrary + a new trigger
    │   ├── worker.py                          gains attacker.session.ended subscription
    │   ├── behavioral.py                      UNCHANGED — networking-domain (LogEvent IATs, beacon detection)
    │   ├── timing.py                          UNCHANGED — networking-domain
    │   └── behave_shell/                      NEW — pure extraction library
    │       ├── __init__.py
    │       ├── extract.py                     orchestration: parse → dispatch → assemble Observations
    │       └── _features/                     per-primitive-family modules
    └── decnet/web/db/models/observations.py   NEW — generic Observation table
```

**No new worker.** The existing `decnet-profiler.service` already
supervises this codepath. No new systemd unit, no new polkit rule, no
new heartbeat. The session-ended handler is a peer to the existing
scoring tick inside the same async loop.

**Audit finding (network vs PTY domains).** `behavioral.py` and
`timing.py` operate on `LogEvent` (network-level connection events
from `decnet.correlation.parser`), feeding the existing
`attacker_behavior` table — TCP fingerprint, OS guess, beacon
interval, behavior class. **Zero overlap with BEHAVE-SHELL**, which
operates on `AsciinemaEvent` (PTY input) and persists to the new
`observations` table. The two coexist; no rewrite, no migration, no
shared state.

Two repos, two commits, no vendoring. `pip install -e
../BEHAVE/core ../BEHAVE/BEHAVE-SHELL` for local dev; pinned wheels in
CI.

## BEHAVE is the spec. DECNET is the engine.

This is a *load-bearing* architectural fact, called out explicitly so
nobody (including future me) misreads the layout.

- **BEHAVE ships:** the primitive registry, the registry-validated
  `Observation` envelope, the bus event adapter, the JSON schema.
  Reference prototype extractor for spec validation only. BEHAVE will
  **not** ship a production engine — that's not what the BEHAVE repo
  is for.
- **DECNET ships:** the production extraction engine. It lives in
  `decnet/profiler/behave_shell/`, written from scratch against the
  BEHAVE spec, called from the existing profiler worker on
  `attacker.session.ended`.

DECNET-side BEHAVE imports are spec-only:

```python
from decnet_behave_core.spec.envelope     import Observation as ObservationEnvelope, Window
from decnet_behave_shell.spec.primitives  import PRIMITIVE_REGISTRY, get as get_primitive_spec
from decnet_behave_shell.spec.event_adapter import event_topic_for, to_event_payload
```

`Observation` is aliased to `ObservationEnvelope` so the storage
SQLModel can keep the `Observation`-flavoured class name where it's
useful, and the BEHAVE primitive-spec accessor is aliased away from
the bare name `get` to avoid shadowing in feature-extractor modules
that read dicts heavily.

That's it. No imports from `BEHAVE/prototype_extractors/`. The
prototype is read as **design notes** during the engine build, then
ignored. If the prototype yields a primitive the production engine
doesn't, that's a calibration delta to investigate, not a regression
in either direction.

### The extraction engine — DECNET-side

```
decnet/profiler/behave_shell/
├── __init__.py            exposes extract_session()
├── extract.py             orchestration: parse → dispatch → assemble Observations
└── _features/             feature-extractor modules, one per primitive family
    ├── motor.py           cadence, paste burst, modality, shell mastery
    ├── cognitive.py       latency class, consistency, branch diversity, feedback loop
    ├── temporal.py        session timing, escalation pattern
    └── ...                others added as primitives are productionised

tests/profiler/behave_shell/
└── _features/             one test module per feature family, against synthetic streams
```

The library is **pure** — no I/O, no bus calls, no DB writes. Events
in → `Iterable[Observation]` out. The split between `extract.py`
(orchestration) and `_features/` (per-family implementations) keeps
each primitive's logic auditable in isolation — including the
threshold tables, which are the part most likely to drift across
calibration cycles. The worker (in `decnet/profiler/worker.py`) owns
all I/O: disk-reach, bus publish, DB upsert.

**The engine is its own first-class effort, not a side-effect of
this integration doc.** The five-class calibration grid is the
acceptance test. Beyond that, it has its own design surface
(threshold calibration methodology, per-primitive confidence scoring,
feature-family precedence rules) that this doc does not attempt to
fully specify — that belongs in a sibling `BEHAVE-EXTRACTOR.md` once
Phase 1 lands and we have the storage shape to write into.

**Calibration knowledge does leak across the repo boundary.** BEHAVE's
`primitives.py` carries empirical calibration notes (e.g. CLAUDE-FF
vs CLAUDE-CL on 2026-05-02) inline in the registry. The clean
separation "BEHAVE = pure spec, DECNET = pure engine" is leakier
than this doc would prefer; both repos must agree on what a primitive
*means* before the engine threshold tables are tuned. Treat the
registry's `notes:` field as ground truth and tune DECNET to match.

### BEHAVE-side commits (rare, for spec changes only)

The only reasons to touch the BEHAVE repo during this integration:

1. The DECNET engine discovers a primitive the registry needs and the
   spec doesn't yet define → registry edit in BEHAVE → version bump
   → DECNET pin update.
2. The envelope schema needs a field DECNET can populate honestly
   (e.g. a structured `evidence_ref` schema) → envelope edit → schema
   `v` bump → `observations.envelope_v` column already tracks it.

These are not blockers for Phase 1. They land iteratively as the
engine matures.

## Versioning

| Axis | Current | DECNET pin |
|---|---|---|
| Envelope schema (`Observation.v`) | `1` | column `observations.envelope_v` tracks it |
| Schema URL | `https://behave.local/schema/observation/v1.json` | — |
| `decnet-behave-core` | `0.1.0` | `>=0.1.0,<0.2` |
| `decnet-behave-shell` | `0.1.0` | `>=0.1.0,<0.2` |

A future `v=2` envelope coexists in the same table without a
destructive migration — query by `envelope_v` when shape diverges.
Bump the cap in `pyproject.toml` when BEHAVE cuts `0.2.0`.

## Data flow

```
                      asciinema shard on disk
                      /var/lib/decnet/artifacts/{decky}/sessrec/sessions-YYYY-MM-DD.jsonl
                                    │
                                    │  disk-reach (host-local, never on bus)
                                    ▼
   bus: attacker.session.ended  ─►  decnet-profiler worker (existing)
   (or poll fallback)                │  → handler in worker.py
                                    │  → calls behave_shell.extract_session(events) → Iterable[Observation]
                                    │  (registry-validated by BEHAVE)
                                    ▼
                    bus.publish(event_topic_for(obs.primitive),
                                to_event_payload(obs))
                                    │
              ┌─────────────────────┼──────────────────────┐
              ▼                     ▼                      ▼
     observations table      AttackerDetail UI      future: attribution engine,
     (DECNET storage)        (live SSE consumer)    federation gossip, webhook export
```

Raw `[t,"i",d]` events never cross the worker→bus boundary. Bus
carries observation envelopes only. Disk-reach for the input stream
mirrors DEBT-047's pattern (filesystem-group-readable artifacts via
DEBT-035).

## Storage — the `observations` table

Generic table holding every BEHAVE envelope field, plus a single
DECNET-side denormalization (`attacker_uuid`) for cheap joins.
**Not a strict 1:1 mirror** — the envelope has no `attacker_uuid`;
DECNET adds it so AttackerDetail doesn't have to chase
`identity_ref → AttackerIdentity → attacker_uuid` on every read.

The SQLModel class is named `ObservationRow` to avoid colliding
with the BEHAVE `Observation` Pydantic class imported into the
same module.

```python
# decnet/web/db/models/observations.py
from decnet_behave_core.spec.envelope import Observation as ObservationEnvelope

class ObservationRow(SQLModel, table=True):
    __tablename__ = "observations"

    # ── envelope fields (types match BEHAVE exactly) ─────────────
    id:              str  = Field(primary_key=True)              # envelope.id (uuid4().hex string)
    identity_ref:    str | None = None                            # envelope.identity_ref (str, not UUID)
    primitive:       str  = Field(index=True)                    # 'motor.keystroke_cadence'
    value:           dict[str, Any] | str | int | float | bool | list = \
                       Field(sa_column=Column(JSON, nullable=False))
    confidence:      float
    window_start_ts: float                                        # flattened from envelope.window
    window_end_ts:   float
    source:          str
    evidence_ref:    str  = Field(nullable=False)                # NOT NULL for DECNET emissions; see "Idempotency"
    envelope_v:      int                                          # envelope.v
    ts:              float = Field(index=True)                   # emission ts

    # ── DECNET-side denormalization (NOT in BEHAVE envelope) ─────
    attacker_uuid:   UUID = Field(foreign_key="attackers.uuid", index=True)

    __table_args__ = (
        Index("ix_observations_attacker_primitive_ts",
              "attacker_uuid", "primitive", "ts"),
        Index("ix_observations_primitive_ts", "primitive", "ts"),
        UniqueConstraint("evidence_ref", "primitive",
                         name="uq_observations_evidence_primitive"),
    )
```

**SQLAlchemy `JSON` not `JSONB`** per the typed-evidence-dicts memory
rule (dual-backend MySQL + SQLite).

**`evidence_ref` is NOT NULL** for DECNET-emitted observations, even
though BEHAVE's envelope makes it `Optional[str]`. The worker's
"have we already profiled this session?" check (see Idempotency
below) keys on `evidence_ref`; if it's NULL the check breaks. The
shape `shard:{decky}/{service}/{date}.jsonl#sid` is mandatory at the
worker layer. If a future BEHAVE consumer needs nullable
evidence_ref, that's a separate observation source with its own
worker — not this one.

**`UniqueConstraint(evidence_ref, primitive)`** enforces idempotency
at the schema level, so a re-run of the worker on the same shard+sid
produces a DB-side conflict, not silent duplicate rows. SQLite and
MySQL both treat distinct (non-NULL) tuples as distinct in unique
indexes — safe across both backends since `evidence_ref` is
NOT NULL.

**No `_migrate_*` helper.** Pre-v1; `SessionProfile` and its `kd_*`
columns are deleted from `decnet/web/db/models/attackers.py`
outright. DEBT-011 (Alembic) remains deferred.

### Canonical queries

**Latest observation per primitive, for one attacker** (AttackerDetail
"current state" panel):

```sql
SELECT primitive, value, confidence, ts
FROM observations
WHERE attacker_uuid = :uuid
  AND ts = (SELECT MAX(ts) FROM observations o2
            WHERE o2.attacker_uuid = observations.attacker_uuid
              AND o2.primitive    = observations.primitive)
ORDER BY primitive;
```

(SQLite — no `DISTINCT ON`; window-function rewrite available if the
correlated subquery hot-spots.)

**Time-series for one primitive across all sessions of one attacker**
(for "is this typist drifting" charts, future):

```sql
SELECT ts, value, confidence
FROM observations
WHERE attacker_uuid = :uuid AND primitive = :primitive
ORDER BY ts;
```

## The session-ended handler — riding the existing profiler worker

```
decnet/profiler/
├── worker.py                EXISTING — gains attacker.session.ended subscription
└── behave_shell/            NEW — pure extraction library (no I/O)
    ├── __init__.py
    └── extract.py           wraps the engine + disk-reach call site

tests/profiler/behave_shell/
├── __init__.py
├── test_extract.py          unit tests against synthetic event streams
├── test_calibration_grid.py the five-class regression suite (Phase 5)
├── test_worker_session_ended_bus.py    FakeBus path
└── test_worker_session_ended_poll.py   DECNET_BUS_ENABLED=false path
```

(All tests live under `tests/`, mirroring the source tree per repo
convention. Existing `tests/profiler/test_session_profile.py` is
deleted alongside the `SessionProfile` model in Phase 1.)

**Trigger.** Subscribe to `attacker.session.ended` on the bus. Poll
fallback walks `Log` rows where `event_type='session_recorded'` and
no `observations` row carries the matching `evidence_ref`. Bus path
ships first; poll fallback ships in the same commit so
`DECNET_BUS_ENABLED=false` is supported from day one (DEBT-031
pattern).

**Disk-reach.** For each `(decky, service, sid)`, resolve the shard
via `_find_shard_with_sid` (already shipped, `323077b`). Open the
JSONL via `decnet/artifacts/paths.py:resolve_artifact_path`
(DEBT-047 — symlink-escape check, regex validation,
`ARTIFACTS_ROOT` env override). Slice the per-sid event list. Pass
to BEHAVE.

**Extraction.** Call
`decnet.profiler.behave_shell.extract_session(events, sid=..., source=...)`.
Receive `Iterable[Observation]`. Each is registry-validated at
construction by BEHAVE's `Observation` subclass; DECNET does not
re-validate.

**Resolve `attacker_uuid`.** Sessrec carries `(decky_name, service,
sid, src_ip, src_port)` per shard line. Resolve src_ip → attacker
via the existing `attackers.ip` index; create-if-missing per the
existing observe path. Stamp `identity_ref=NULL` until attribution
exists.

**Bus emission.** For each observation, **DECNET overrides BEHAVE's
adapter** to preserve sensor-side identifiers across the bus:

```python
# BEHAVE's to_event_payload() excludes id/ts/v because BEHAVE assumes
# the bus envelope carries them at the Event level. DECNET's bus
# (DEBT-029) auto-generates fresh id/ts/v on publish — there's no
# bus.publish overload that accepts envelope-level overrides. Without
# this merge, BEHAVE's id/ts/v would be silently lost, breaking
# cross-host dedup and federation gossip.
payload = to_event_payload(obs) | {"id": obs.id, "ts": obs.ts, "v": obs.v}

bus.publish(
    topic   = event_topic_for(obs.primitive),    # 'attacker.observation.motor.keystroke_cadence'
    payload = payload,
)
```

Subscribers reconstructing the envelope via
`from_event_payload(primitive, payload)` see the original BEHAVE id /
ts / v because they ride along in `payload`. The DECNET-bus Event
envelope's *own* id/ts/v (auto-generated) are bus-routing concerns,
distinct from observation identity.

**This is a known deviation from BEHAVE's wire-format docstring**
(`core/decnet_behave_core/spec/envelope.py:77-84`). If DECNET's bus
later grows envelope-level overrides on `publish()`, revert to the
upstream contract. Filed as a low-priority follow-up — not blocking.

Adapter import path is pure-stdlib — no DECNET imports inside BEHAVE.
DECNET is the consumer of BEHAVE's contract, never the other way
around.

**Persistence.** All observations from one session — i.e. one
`(decky, service, sid)` triple — commit as **a single transaction**.
Either the entire session lands in `observations` or none of it
does; partial-failure mid-session never leaves a half-profiled
attacker row.

Persist **first**, then publish to the bus best-effort. Bus is
fire-and-forget (DEBT-029 §6) — a publish failure does **not** roll
back the persisted rows, and a persist failure means nothing is
published. DB is the source of truth; the bus is the notification
layer only. Order matters: a downstream subscriber receiving an
`attacker.observation.*` event can immediately query the table and
find it; the inverse (publish-then-persist) would create a window
where subscribers chase rows that don't exist yet.

**Idempotency.** Enforced at the schema level by
`UniqueConstraint(evidence_ref, primitive)`. Re-running the worker
on the same shard+sid produces a DB-side conflict per row, which the
worker handles via `INSERT … ON CONFLICT DO UPDATE` (SQLAlchemy
upsert). Worker marks a session "profiled" by the existence of any
row matching its `evidence_ref` — no separate marker column. Because
the unique index makes accidental duplicates structurally
impossible, the marker check is honest.

## Bus topics

Add to `decnet/bus/topics.py`:

```python
ATTACKER_OBSERVATION_PREFIX = "attacker.observation"
# Wildcard patterns:
#   attacker.observation.motor.*
#   attacker.observation.cognitive.*
#   attacker.observation.>            (everything BEHAVE-SHELL emits)
```

Topic shape locked by BEHAVE's `event_topic_for()`; DECNET registers
the prefix for documentation and pattern-matching only. **Bus auth
is not topic-level** — per DEBT-029 §2 the bus uses
kernel-authenticated peer delivery (UNIX socket file permissions),
not topic ACLs. `bus/topics.py` change co-commits with a
wiki-checkout `Service-Bus.md` update (memory rule: "Document new
bus signals in the wiki").

## AttackerDetail consumer

### REST surface

`decnet/web/router/attackers/api_get_attacker_detail.py` swaps the
`SessionProfile` join for the latest-per-primitive query above.
Response shape gains:

```jsonc
{
  // ... existing attacker fields ...
  "observations": [
    {
      "primitive":  "motor.input_modality",
      "value":      "pasted",
      "confidence": 0.91,
      "ts":         1714521660.456,
      "source":     "decnet/profiler/behave_shell/extract.py"
    },
    // ... one row per primitive observed for this attacker ...
  ]
}
```

Frontend (`AttackerDetail.tsx`) renders a "Behavioural primitives"
panel grouped by the registry's top-level domain (`motor.*`,
`cognitive.*`, `temporal.*`, `operational.*`, `environmental.*`,
`cultural.*`, `emotional_valence.*`, `toolchain.*`). Day-one render
priorities for the panel:

1. `motor.input_modality` — pasted vs typed vs mixed
2. `cognitive.feedback_loop_engagement` — closed_loop vs fire_and_forget
3. `cognitive.command_branch_diversity` — linear_playbook vs adaptive_branching
4. `cognitive.inter_command_latency_class` — typing_speed / llm_lightweight / llm_heavyweight / long
5. Everything else, alphabetised by primitive path.

These four are the highest-discriminative-value primitives in the
calibration grid; surfacing them first is what unblocks the "is this
the same operator class" hover story.

### Live-update SSE route

`GET /api/v1/attackers/{uuid}/events` — per-attacker SSE stream,
mirrors the per-topology pattern shipped in DEBT-030.
The route subscribes to `attacker.observation.*` filtered by
`identity_ref` / resolved `attacker_uuid`, plus
`attacker.fingerprint_rotated` / `attacker.scored` for the same
attacker.

Envelope identical to topology events:
`{v, type, ts, payload}`. Day-one event types:
`observation.<primitive>`, `fingerprint.rotated`, `attacker.scored`.

Auth: `?token=` query-param matching the existing per-topology and
`/stream` pattern. Snapshot-on-connect serves the latest-per-primitive
query result so the panel hydrates immediately, then live-forwards
bus events. 15s keepalive, mirrors the topology route.

The global `/stream` is **not** the right fit here — it fans out
every attacker's events to every subscriber, and the AttackerDetail
page only cares about one. Per-attacker route, like
per-topology.

## PII discipline

Binds at the BEHAVE layer; DECNET does not get to "improve" the
envelope by reading raw bodies into payloads.

- Raw `[t,"i",d]` keystroke events stay on disk. Worker reads,
  extracts, discards.
- `evidence_ref` is a *pointer* (`shard:path#sid`), never the
  evidence itself.
- `value` JSON is bounded by the registry's `ValueTypeSpec` — no
  free-form blobs that could smuggle keystrokes.
- Bigram simhashes (when emitted via `cognitive.*` digraph
  primitives) are *characters*, not *content* — already documented in
  BEHAVE's primitives module.

**Canonical PII binding.** The authoritative statement is the module
docstring at `core/decnet_behave_core/spec/envelope.py:3-19` — it
forbids raw keystrokes, command bodies, credentials, and payload
bytes in observation values; `evidence_ref` is a pointer, never the
evidence. That docstring is binding on this DECNET integration.
*Not* `BEHAVE-SHELL/scratchpad.md` — scratchpads, by definition,
aren't binding policy surfaces.

## Calibration grid IS the regression test

`tests/profiler/behave_shell/test_calibration_grid.py` runs the
**pure engine** (`behave_shell.extract_session()` called directly,
no worker, no bus, no DB) against each of the five
`BEHAVE/prototype_extractors/shell/sessions-2026-05-02-*.jsonl`
shards (gitignored — fixture path resolved via
`BEHAVE_CALIBRATION_DIR` env var, skipped if unset). Asserts the
expected primitive set fires per class:

| Shard | Class | Required primitives in output |
|---|---|---|
| `sessions-2026-05-02.jsonl` | HUMAN | `motor.input_modality=typed`, `cognitive.inter_command_consistency=bimodal`, `cognitive.feedback_loop_engagement=closed_loop`, `cognitive.command_branch_diversity=adaptive_branching` |
| `sessions-2026-05-02-with-llm.jsonl` | YOU-sim | `motor.input_modality=pasted`, `motor.paste_burst_rate=occasional`, `cognitive.inter_command_latency_class=typing_speed`, `cognitive.command_branch_diversity=linear_playbook` |
| `sessions-2026-05-02-new.jsonl` | LW-sim | `motor.input_modality=pasted`, `motor.paste_burst_rate=habitual`, `cognitive.inter_command_latency_class=llm_lightweight`, `cognitive.command_branch_diversity=linear_playbook` |
| `sessions-2026-05-02-with-claude.jsonl` | CLAUDE-FF | `motor.input_modality=pasted`, `motor.paste_burst_rate=habitual`, `cognitive.inter_command_latency_class=llm_heavyweight`, `cognitive.command_branch_diversity=linear_playbook`, `cognitive.feedback_loop_engagement=fire_and_forget` |
| `sessions-2026-05-02-closed-loop.jsonl` | CLAUDE-CL | `motor.input_modality=pasted`, `motor.paste_burst_rate=habitual`, `cognitive.inter_command_latency_class=long`, `cognitive.command_branch_diversity=adaptive_branching`, `cognitive.feedback_loop_engagement=closed_loop` |

Any extractor change that breaks one of these classifications fails
CI. The grid is the discriminative-power floor — calibration
refinement can *add* primitives, never silently *drop* them.

## Phase plan

Per the "commit per task" memory rule, each phase ships as one commit
with its own tests.

### Phase 1 — DECNET-side storage (no BEHAVE coupling yet)

- New `observations` table + SQLModel + repository methods.
- Drop `SessionProfile` + `kd_*` columns from
  `decnet/web/db/models/attackers.py`.
- AttackerDetail API switches to the latest-per-primitive query.
  Returns empty `observations: []` since nothing populates the table.
- `decnet/bus/topics.py` registers `attacker.observation.*` prefix.
- Tests: SQLModel CRUD, latest-per-primitive query against fixture
  rows, empty-attacker contract.

### Phase 2 — DECNET extraction engine (`decnet/profiler/behave_shell/`)

- Production extractor written against the BEHAVE spec, pure library
  (no I/O).
- One feature-family module per `_features/{motor,cognitive,temporal,...}.py`.
- Public entry: `extract_session(events, *, sid, source) -> Iterable[Observation]`.
- Tests in `tests/profiler/behave_shell/_features/`: per-feature unit
  tests against synthetic event streams. The calibration-grid suite
  (Phase 5) is the integration test.
- This phase has its own design surface — see `BEHAVE-EXTRACTOR.md`
  (filed as a sibling doc when Phase 1 lands). Phases 1 and 2 are
  largely independent; can run in parallel.

### Phase 3 — BEHAVE pin

- `pyproject.toml` pins `decnet-behave-core` and `decnet-behave-shell`
  at whatever versions the engine settles on.
- CI install-time smoke: registry imports cleanly, envelope validates
  a known-good observation.

### Phase 4 — Wire the trigger into the existing profiler worker

- `decnet/profiler/worker.py` gains an `attacker.session.ended`
  subscription handler.
- Handler does: resolve shard via disk-reach → call
  `behave_shell.extract_session()` → upsert into `observations` table
  → publish each observation on the bus.
- Poll fallback for `DECNET_BUS_ENABLED=false`.
- Trigger isolation: handler exceptions logged, do not affect the
  existing scoring tick.
- Tests in `tests/profiler/behave_shell/`: FakeBus path, poll-only
  path, disk-reach error paths, idempotency on re-run.
- **No new systemd unit.** The existing `decnet-profiler.service`
  already supervises this code.

### Phase 5 — Calibration regression suite + UI surface

- `tests/profiler/behave_shell/test_calibration_grid.py` against all
  five BEHAVE shards.
- New `GET /api/v1/attackers/{uuid}/events` SSE route (mirrors the
  per-topology pattern from DEBT-030); snapshot-on-connect +
  bus-forwarded `attacker.observation.*` events. Tests in
  `tests/api/attackers/test_events_stream.py`.
- AttackerDetail.tsx renders the Behavioural primitives panel and
  consumes the SSE route for live updates.
- Frontend Vitest coverage for the panel (DEBT-043 harness, shipped).

### Phase 6 — Live smoke

- Ship a decky, run a real SSH session from each calibration class
  manually, disconnect, observe `observations` rows + bus events +
  AttackerDetail panel.
- Document the smoke procedure in
  `scripts/behave_shell/smoke.sh` (parallel to
  `scripts/bus/smoke-mutator.sh` — per-feature dirs).

## Out of scope

Filed for future paydown when they bite. Do not let them creep into
this integration.

- **Attribution engine.** Consumes `attacker.observation.*`, emits
  `attribution.profile.candidate.*`. BEHAVE explicitly separates
  observation from attribution.
- **Federation gossip** of observations across swarm hosts.
- **Backfill** over historical shards (one-shot script when the
  table lands; not a worker feature).
- **Webhook export** of observation streams (rides DEBT-037).
- **Observation retention / vacuum.** Pre-v1, no users to mislead;
  filed when storage actually pressures.
- **`SessionProfile` data migration.** None — table ships empty
  today, drop is destructive but lossless.
- **Cross-domain BEHAVE** (BEHAVE-TEXT integration for stylometric
  analysis of attacker-typed messages, e.g. captured emails). Same
  `observations` table will accept those envelopes when their primitive
  registry is registered, but the wiring is a separate paydown.

## Resolved decisions (formerly open questions)

- **Q1 — engine location.** RESOLVED: BEHAVE's prototype is reference
  code only, never imported by DECNET. The production extraction
  engine lives in `decnet/profiler/behave_shell/` as a sublibrary of
  the existing profiler worker — no new daemon, no new systemd unit.
  (See "BEHAVE is the spec. DECNET is the engine.")
- **Q2 — emission granularity.** RESOLVED: **per-(sid, primitive).**
  Every session emits its full primitive set; every emission
  persists. The schema already supports it; this just locks in the
  worker write loop. *More detail the better.*
- **Q3 — cross-session aggregation, day one.** RESOLVED: latest wins
  per primitive in the AttackerDetail "current state" query. Simple,
  honest, easy to reason about.

## Real open question — Cross-session aggregation, the right way

Q3's "latest wins" is a stopgap. The actual question is harder and
deserves its own design pass before AttackerDetail starts surfacing
attribution-flavoured claims:

> **When two sessions from the same attacker (or identity) emit
> conflicting values for the same primitive, what does the
> attacker-level view say?**

Concrete cases:

- Session A: `motor.input_modality = typed` (conf 0.92).
  Session B (next day): `motor.input_modality = pasted` (conf 0.88).
  Is this attacker `mixed`? Or did they switch tooling? Or did a
  *different operator* take over the same credentialed access?
- `cognitive.feedback_loop_engagement` flips from `closed_loop` to
  `fire_and_forget` between two sessions. Is this fatigue, a
  handoff (`operational.multi_actor_indicators=handoff_detected`?),
  or a script taking over from a human?
- `cognitive.command_branch_diversity = unknown` in a short session
  vs `adaptive_branching` in a long session. Latest-wins would
  collapse this to `unknown` if the short session lands second —
  exactly the wrong answer.

**This is genuinely an attribution-engine concern**, not an
extraction concern. BEHAVE is firm on that bright line. The clean
answer is:

1. **DECNET stores all observations** (per-sid, per-primitive — Q2).
2. **AttackerDetail's day-one "current state" query is latest-wins**
   (Q3) — not because it's right, but because it's *honestly
   transparent* about being naïve.
3. **The right answer ships with the attribution engine** as a
   separate paydown — likely as new `attribution.profile.*` topics
   that emit a *derived* per-attacker primitive map with explicit
   merge semantics (`stable` / `drifting` / `conflicted` /
   `multi_actor`). Day-zero, that engine doesn't exist; day-one,
   AttackerDetail just shows raw latest values + a "N
   observations" hover.

Filed as **DEBT-051 — Cross-session BEHAVE primitive aggregation
(attribution engine)** when this doc is reviewed. Out of scope for
this integration; explicitly listed under "Out of scope" above.

---

**Owner:** ANTI.
**Implementation gate:** this doc reviewed → Phase 1 starts.
