# Attribution Engine — Design

**Status:** pre-implementation. This doc is the spec; code follows.
**Tracks:** DEBT-051 (cross-session BEHAVE primitive aggregation —
named in `BEHAVE-INTEGRATION.md`).
**Depends on:** `IDENTITY_RESOLUTION.md` (substrate shipped — table,
FK, lifecycle topics), `BEHAVE-INTEGRATION.md` (observation
producer), `DEBT-032` (fingerprint rotation, shipped).
**Engine home:** this repo, `decnet/correlation/attribution/`
(sublibrary inside the existing correlation worker — no new daemon).

## Premise

DECNET has three layers stacked above raw events. After
`BEHAVE-INTEGRATION.md` ships, we have:

| Layer | What it stores | What it knows |
|---|---|---|
| **Observation** | `observations` table, one row per (sid, primitive) | "I saw value V for primitive P, sourced from session S, at time T, with confidence C." |
| **Attacker** | `attackers` table, one row per source IP | "These observations all came from IP X." |
| **Identity** | `attacker_identities` table (empty today — `IDENTITY_RESOLUTION.md`) | "These N attacker rows are the same hands." |

BEHAVE *emits*. Attackers are *observed*. The attribution engine is
the layer that **concludes** — it links observations into identities
and surfaces a per-identity primitive map with explicit merge
semantics. This doc specifies it.

## The bright line — lifted from BEHAVE, binding here

The BEHAVE envelope module docstring
(`core/decnet_behave_core/spec/envelope.py:20-26`) draws an explicit
bright line:

> Explicitly NOT for: identity attribution to named natural persons;
> access or admission decisions; biometric login; ML-driven user
> identification. Those framings push into legal/ethics territory the
> project will not walk into by accident.

That binding statement carries forward. The attribution engine:

- **Links observations to opaque identity UUIDs**, never to named
  persons.
- **Emits probabilistic linkage**, never certainty.
- **Does not gate access** to anything — it's an analytics surface.
- **Does not output classifier verdicts** about "good" vs "bad"
  operators; it surfaces *behavioural coherence* (these observations
  cluster) and *behavioural drift* (this identity's primitives are
  changing), and stops there.

Crossing this line is grounds for ripping the engine out and
starting over.

## What the engine IS, what it IS NOT

| IS | IS NOT |
|---|---|
| A clusterer + state machine over BEHAVE observations | A keystroke-dynamics extractor (that's the engine in `BEHAVE-EXTRACTOR.md`) |
| The thing that writes `attacker_identities` rows | The thing that decides whether to block/alert/page on an attacker |
| The producer of `attribution.profile.*` events | The producer of `attacker.observation.*` events |
| Honest about uncertainty (every claim carries a confidence) | A binary classifier with an arbitrary threshold |
| Replayable / deterministic given the same observation sequence | A black-box ML model |

## Architectural placement

```
/home/anti/Tools/DECNET/
├── decnet/correlation/                  EXISTING worker — gains a sublibrary + a new trigger
│   ├── worker.py                        gains attacker.observation.* subscription
│   ├── fingerprint_rotation.py          UNCHANGED — already shipped (DEBT-032)
│   └── attribution/                     NEW — pure attribution library
│       ├── __init__.py                  exposes link_observation(), aggregate_identity()
│       ├── linkage.py                   "which identity does this observation belong to?"
│       ├── aggregate.py                 per-(identity, primitive) merge state machine
│       ├── _signals/                    per-signal scorers (jarm, hassh, kd, c2, ip)
│       └── _thresholds.py               named constants, calibration-cited
└── decnet/web/db/models/
    ├── attacker_identities.py           EXISTING (IDENTITY_RESOLUTION.md substrate)
    └── attribution_state.py             NEW — per-(identity, primitive) state rows
```

**No new worker.** The existing `decnet-correlation.service`
supervises this codepath. The correlation worker already owns
cross-attacker reasoning (DEBT-032 fingerprint rotation lives there).
Attribution is a natural peer.

**Audit finding (correlation vs profiler).** Profiler emits
observations per-session (BEHAVE-SHELL extraction). Correlation
consumes observations across sessions and decides identity. Two
roles, two workers, clean cut. **Don't mix them.**

## Two responsibilities, kept separate

The engine has **two axes of work**, often confused:

### Axis 1 — Linkage

> "This new observation arrived. Which identity does it belong to?"

Inputs: one observation (just arrived) + the existing identity table.
Output: one of {`assign-to-existing(uuid)`, `create-new()`,
`defer(reason)`}.

Lives in `attribution/linkage.py`. Reads
`attacker.observation.*` events; writes `attacker_identities` rows
and `attackers.identity_id` FK; emits `identity.formed` /
`identity.observation.linked` (existing topics from
`IDENTITY_RESOLUTION.md`).

### Axis 2 — Aggregation

> "Given an identity's full observation history, what's the
> per-primitive summary I should surface to AttackerDetail /
> IdentityDetail?"

Inputs: all observations linked to one identity. Output: a
per-primitive state map: `{primitive: (current_value, state, confidence, dispersion)}`
where `state ∈ {stable, drifting, conflicted, multi_actor, unknown}`.

Lives in `attribution/aggregate.py`. Pure function — given the same
observation set, returns the same state map (replayability is
non-negotiable).

**These two axes are separable.** v0 ships **aggregation only** (over
single-`attacker_uuid` proto-identities), solves DEBT-051. v1 adds
linkage (real clustering across attacker_uuids). v2 adds federation.
This ordering is deliberate — aggregation has narrower failure modes
and doesn't require the linkage signals to be calibrated yet.

## v0 / v1 / v2 ladder

### v0 — Aggregation over per-attacker proto-identities

The substrate of `IDENTITY_RESOLUTION.md` ships empty: every
`attackers` row has `identity_id = NULL`. No clusterer means no
identity rows. v0 sidesteps this honestly: **treat each
`attacker_uuid` as its own proto-identity** and aggregate
observations over it.

What v0 delivers:
- Per-(attacker_uuid, primitive) merge state machine.
- New `attribution_state` table holding the derived state.
- New `attribution.profile.*` bus topics emitting state transitions.
- AttackerDetail's "current state" panel gains state badges
  (`stable / drifting / conflicted`) replacing today's naïve
  latest-wins surface from `BEHAVE-INTEGRATION.md` Q3.

What v0 does NOT do:
- No clustering across IPs.
- No identity rows ever populated.
- `IdentityDetail.tsx` (already built per `IDENTITY_RESOLUTION.md`)
  stays unreached — there are no identities yet.

**v0 closes DEBT-051.** That's the explicit scope.

### v1 — Linkage (real clustering)

What changes:
- Clusterer subscribes to high-confidence rotation-resistant signals
  (HASSH, payload simhashes, keystroke-dynamics simhash,
  C2 callbacks) and groups `attacker_uuid`s under
  `attacker_identities.uuid`.
- v0's aggregation engine retargets from `attacker_uuid` to
  `identity_uuid` once a cluster forms.
- `identity.formed` / `identity.observation.linked` /
  `identity.merged` (existing topics) start firing.
- IdentityDetail.tsx starts seeing rows.

What v1 does NOT do:
- No federation. Cluster decisions are master-local.
- No retroactive observation re-linking once an identity is committed
  (that's a v1.5 problem, "stable" identities should be hard to
  un-link silently).

### v2 — Federation gossip

What changes:
- Identities + their primitive-state maps gossip over the existing
  swarm mTLS infra to peer masters.
- `schema_version` field on `attacker_identities`
  (`IDENTITY_RESOLUTION.md` Risk #3) becomes load-bearing.
- Trust model is **social**, not cryptographic
  (memory rule: federation trust is invite-based/human).

Out of scope for this doc beyond noting it exists. Federation gets
its own design pass.

---

## v0 design — Aggregation state machine

The whole reason DEBT-051 was filed. This is the load-bearing piece.

### State definitions

For each `(attacker_uuid, primitive)` pair, the engine maintains a
state from this set:

| State | Meaning | When to assert |
|---|---|---|
| `unknown` | Insufficient observations to classify | Default; < 3 observations OR all-`unknown` values |
| `stable` | Recent observations agree | Last N observations all share the same value |
| `drifting` | Recent observations disagree with older | Recent N != older N, but recent N is internally consistent |
| `conflicted` | Recent observations disagree with each other | Recent N is split (no majority) |
| `multi_actor` | Strong signal that two operators share access | Conflicted + alternation pattern (operator A → B → A → B), not random flip |

### Per-primitive merge logic

The engine carries a per-`ValueKind` merge function. Categorical
primitives dominate the calibration grid; numeric and hash primitives
need different math:

#### Categorical (`motor.input_modality`, `cognitive.feedback_loop_engagement`, etc.)

Last-N window comparison. With `N = 5` (configurable in
`_thresholds.py`):

```
recent_5  = observations[-5:]
older_5   = observations[-10:-5]    # if available

if all(o.value == recent_5[0].value for o in recent_5):
    if older_5 and all(o.value == older_5[0].value for o in older_5):
        if recent_5[0].value != older_5[0].value:
            state = drifting
        else:
            state = stable
    else:
        state = stable    # consistent with no older comparison
elif majority_value(recent_5):
    state = stable        # tolerant — one outlier in five is fine
else:
    state = conflicted
```

`multi_actor` triggers on conflicted + temporal alternation
(operator A and B observations interleave on a session-level granularity,
not just within one session). Lower-confidence detection;
v0 emits at confidence ≤ 0.6 by design.

#### Numeric (`toolchain.c2.beacon_interval_ms`, etc.)

EWMA + dispersion. State = `stable` if dispersion < 20% of mean,
`drifting` if mean shifts > 30% over recent window, `conflicted`
if dispersion > 100%.

#### Hash (`toolchain.tls.jarm_server`, `toolchain.ssh.hassh_client`)

Already handled by DEBT-032 fingerprint rotation. Attribution engine
*reads* `attacker.fingerprint_rotated` events, doesn't recompute.
State = `stable` if no rotation, `drifting` if 1-2 rotations,
`conflicted` if > 2 rotations in a tight window.

### Storage — the `attribution_state` table

Materialised view of the state machine. Re-derivable from
`observations` + DEBT-032's rotation log; this table is a cache for
cheap reads, not a source of truth.

```python
# decnet/web/db/models/attribution_state.py

class AttributionStateRow(SQLModel, table=True):
    __tablename__ = "attribution_state"

    # ── key ────────────────────────────────────────────────
    attacker_uuid:   UUID = Field(foreign_key="attackers.uuid", primary_key=True)
    primitive:       str  = Field(primary_key=True)

    # ── derived state ──────────────────────────────────────
    current_value:   dict[str, Any] | str | int | float | bool | list = \
                       Field(sa_column=Column(JSON, nullable=False))
    state:           str          # 'stable' | 'drifting' | 'conflicted' | 'multi_actor' | 'unknown'
    confidence:      float        # engine's confidence in the state assertion (not in any verdict)
    observation_count: int        # how many observations underlie this state
    last_change_ts:  float        # when state last flipped
    last_observation_ts: float    # most recent observation that fed this row

    # ── audit ──────────────────────────────────────────────
    schema_version:  int = 1      # for federation, mirrors AttackerIdentity convention
    updated_at:      float

    __table_args__ = (
        Index("ix_attribution_state_state", "state"),
        Index("ix_attribution_state_last_change", "last_change_ts"),
    )
```

`(attacker_uuid, primitive)` is the composite PK — at most one state
row per pair. v1 will rename `attacker_uuid` to a polymorphic
`subject_uuid` keyed on either attackers or identities (deferred —
don't pre-build the polymorphism before clustering ships).

### Bus topics

New, distinct from `IDENTITY_RESOLUTION.md`'s `identity.*` lifecycle
topics:

| Topic | Payload | When |
|---|---|---|
| `attribution.profile.state_changed` | `{attacker_uuid, primitive, old_state, new_state, current_value, confidence, ts}` | State transitions (e.g. `stable` → `drifting`) |
| `attribution.profile.multi_actor_suspected` | `{attacker_uuid, primitives: [], evidence_summary, confidence, ts}` | When ≥ 2 primitives independently signal `multi_actor`; correlation is the trigger, not any single primitive |

`identity.*` topics from `IDENTITY_RESOLUTION.md` stay reserved for
v1 (clusterer-emitted lifecycle events). v0 doesn't touch them.

**Wiki:** `Service-Bus.md` documents these in the same commit that
adds the constants (`feedback_wiki_bus_signals`).

### API surface

```
GET /api/v1/attackers/{uuid}/attribution
  → {
      "primitives": [
        {
          "primitive": "motor.input_modality",
          "current_value": "pasted",
          "state": "stable",
          "confidence": 0.91,
          "observation_count": 7,
          "last_change_ts": 1714521660.456
        },
        ...
      ]
    }
```

AttackerDetail.tsx merges this with the latest-per-primitive query
from `BEHAVE-INTEGRATION.md`. The state badge is the new bit.

The SSE route from `BEHAVE-INTEGRATION.md`
(`GET /api/v1/attackers/{uuid}/events`) gains forwarded
`attribution.profile.state_changed` events so the badge updates live.

---

## Linkage signals (v1 — not v0)

For when v0 is stable and we promote attacker_uuid → identity_uuid.
Documented here so v0 doesn't paint into a corner.

### Signal weights

Each signal contributes to a linkage score. Two `attacker_uuid`s
with combined score above the threshold get clustered.

| Signal | Strength | Why | Cost |
|---|---|---|---|
| Same `kd_digraph_simhash` (Hamming distance < 8) | **STRONG** | Keystroke rhythm is hard to fake without effort | Computed at session-end by BEHAVE engine |
| Same C2 callback endpoint | **STRONG** | Operator infra is sticky | Already extracted |
| Same `hassh_client` | MEDIUM | Tools change less than IPs | Already in `attacker_behavior` |
| Same `jarm_server` (if attacker exposes services) | MEDIUM | Probed-attacker substrate (DEBT-032) | Already shipped |
| Same `tcp_fingerprint` cluster | WEAK | OS info, easily collided | Already in `attacker_behavior` |
| Same source IP | **REJECT** | Triggers naïvely on NAT collisions; never use IP alone | n/a |

### Threshold

Single combined score, calibrated against:
- **False merges**: two distinct attackers collapsed into one (silent
  miscount). HARD failure — engine refuses to merge below ~0.85.
- **Missed merges**: two observations from the same operator
  unrelated. Soft failure — operator can review unmerged candidates
  in IdentityDetail's "candidate links" panel and merge manually.

The threshold lives in `_thresholds.py` like the BEHAVE-SHELL
engine's; calibration cycle ships with the linkage code.

### Soft-merge audit trail

`attacker_identities.merged_into_uuid` already exists from
`IDENTITY_RESOLUTION.md`. v1 uses it. When the clusterer reverses an
earlier merge (rare but real), the loser row's `merged_into_uuid` is
NULLed and a `attribution.profile.split_proposed` event surfaces in
the operator's review queue.

---

## Phase plan

Per the "commit per task" + "tests per task" memory rules. Each
phase is one commit.

### Phase 1 — Schema + topics + empty handler

- New `attribution_state` SQLModel + migration (none needed pre-v1,
  per the memory rule — just edit the model).
- `decnet/bus/topics.py` registers `attribution.profile.*` prefix.
- `decnet/correlation/worker.py` gains an
  `attacker.observation.*` subscription handler that does
  **nothing yet** — just logs. Proves the wiring.
- Wiki `Service-Bus.md` update co-commits.
- Tests: SQLModel CRUD on `attribution_state`, bus subscription
  handler is exercised by FakeBus.

Commit: `feat(correlation/attribution): substrate + idle handler`.

### Phase 2 — Categorical merge function

- `attribution/aggregate.py:_aggregate_categorical(observations) → (value, state, confidence)`.
- Implements the last-N comparison logic above.
- Pure function. Synthetic-input tests covering each state transition
  (unknown → stable → drifting → stable, conflicted, multi_actor).
- No DB, no bus, no I/O.

Commit: `feat(correlation/attribution): categorical merge state machine`.

### Phase 3 — Hash + numeric merge functions

- `_aggregate_hash` reads `attacker_fingerprint_rotation` events
  (DEBT-032 already produces them).
- `_aggregate_numeric` does EWMA + dispersion.
- Per-`ValueKind` dispatcher in `aggregate.py` picks the right
  function.
- Tests for each value-kind path.

Commit: `feat(correlation/attribution): hash + numeric merge functions`.

### Phase 4 — Wire into the worker

- Subscription handler reads each `attacker.observation.*` event,
  loads the prior `AttributionStateRow` (if any), runs the merger,
  upserts the new state, emits `attribution.profile.state_changed`
  on transition.
- Trigger isolation: handler exceptions logged, do not affect
  fingerprint-rotation or any other correlator path.
- Tests: end-to-end with FakeBus + in-memory DB, observation-in →
  state-row-out + transition-event-out.

Commit: `feat(correlation/attribution): wire bus handler, persist state`.

### Phase 5 — `multi_actor_suspected` cross-primitive correlator

- Periodic tick (every 60s default — configurable) walks
  `attribution_state` rows where `state = 'multi_actor'`, groups by
  `attacker_uuid`, fires
  `attribution.profile.multi_actor_suspected` if ≥ 2 primitives flag
  the same attacker_uuid concurrently.
- Tests: synthetic state rows, assert event fires only on co-flag.

Commit: `feat(correlation/attribution): cross-primitive multi-actor detection`.

### Phase 6 — API surface

- `GET /api/v1/attackers/{uuid}/attribution` route + Pydantic model.
- AttackerDetail.tsx renders state badges per primitive in the
  Behavioural Primitives panel.
- SSE route forwarding `attribution.profile.state_changed` events
  filtered by attacker_uuid.
- Frontend Vitest coverage.

Commit: `feat(web): expose attribution state on AttackerDetail`.

### Phase 7 — v0 lockdown

- Synthetic calibration scenarios (extending the BEHAVE-SHELL
  calibration grid concept):
  - "Stable HUMAN over 7 sessions" → all primitives `stable`
  - "HUMAN switches to LLM mid-week" → primitives flip
    `stable` → `drifting`
  - "Two operators alternating on shared creds" → ≥ 2 primitives
    flag `multi_actor`
  - "Single short session" → all primitives `unknown`
- All four scenarios green in CI.

Commit: `test(correlation/attribution): v0 calibration lockdown`.

---

## Out of scope

Filed for future paydown when they bite. Do not let them creep into
v0.

- **Linkage / clustering across attacker_uuids.** That's v1.
- **Federation gossip of identities.** That's v2.
- **Identity-level intel** (`attacker_identity_intel` from
  `IDENTITY_RESOLUTION.md`). Different lifecycle, ships with v1.
- **Manual operator merge UI.** Operators can't fix clusterer
  mistakes from the dashboard — the read-only API stays read-only
  in v0. Editable identity rows are a v1 concern.
- **Retroactive re-aggregation** when thresholds change. v0
  recomputes lazily on next observation per attacker; no batch
  re-walk.
- **Confidence calibration against ground truth.** No ground-truth
  data exists yet. v0 confidence values are heuristic; calibration
  ships when red-team exercises produce labelled trace data.
- **Persona-classification** (e.g. "this identity behaves like a
  bot"). The bright line forbids this. State machine emits
  *coherence* and *drift*, not classifier labels.

## Resolved decisions

- **Where the engine lives.** RESOLVED:
  `decnet/correlation/attribution/`, sublibrary inside the existing
  correlation worker. No new daemon. Symmetric with BEHAVE-SHELL's
  placement under `decnet/profiler/behave_shell/`.
- **Linkage vs aggregation separation.** RESOLVED: two axes, two
  modules (`linkage.py` / `aggregate.py`). v0 ships aggregation
  only.
- **Topic namespace.** RESOLVED: `attribution.profile.*` for
  derived state, distinct from `IDENTITY_RESOLUTION.md`'s
  `identity.*` lifecycle topics. The two namespaces compose; they
  don't overlap.
- **State machine vocabulary.** RESOLVED:
  `unknown / stable / drifting / conflicted / multi_actor`.
  Five states, no more (resist the urge to grow the enum).
- **Subject of attribution in v0.** RESOLVED: `attacker_uuid`,
  not `identity_uuid`. v1 widens.

## Real open questions

These are not stoppers for v0 but need answers before the engine
ships beyond v0.

1. **`multi_actor` false-positive cost.** A flapping primitive can
   look like multi-actor when it's really an operator on a flaky
   network or split between phone/laptop. v0's confidence ≤ 0.6 cap
   helps but doesn't eliminate it. Open: what's the operator-facing
   UX for a `multi_actor` claim that's wrong?
2. **Window size `N`.** v0 hardcodes `N=5` for last-N comparison.
   This is calibrated against typical session counts (most attackers
   are observed < 10 times before they go quiet). Operators with
   long-running attackers (resident threats) may want a wider
   window; needs config knob in v1.
3. **Primitive-weight asymmetry.** Today every primitive contributes
   equally to the implicit "is this attacker behavioural-stable?"
   summary. But `motor.input_modality` is far more discriminative
   than `temporal.weekend_cadence`. Open: do we expose primitive
   weights in the API, or just sort by confidence?
4. **Observation-to-row contention.** A burst of observations for
   the same `(attacker_uuid, primitive)` pair (e.g. a long session
   with 50 sub-observations) hits the same row 50 times. v0 reads
   the row, runs the merger, writes back — under load this is a
   serialised hot path. Open: should the merger batch-process within
   one tick, or is per-observation latency cheap enough?
5. **What happens to `attribution_state` rows when an
   `attacker_uuid` is deleted?** No `attackers` deletion path
   exists today, but if/when one ships (GDPR purge, federation
   resync), `ON DELETE CASCADE` is the obvious choice. File when it
   matters.

---

## Implementation order checklist

A single page you can paste into a TODO and tick off:

- [ ] Phase 1 — Schema + topics + idle handler
- [ ] Phase 2 — Categorical merge function (pure, no I/O)
- [ ] Phase 3 — Hash + numeric merge functions
- [ ] Phase 4 — Wire bus handler, persist state
- [ ] Phase 5 — `multi_actor_suspected` cross-primitive correlator
- [ ] Phase 6 — API + AttackerDetail badges + SSE forwarding
- [ ] Phase 7 — v0 calibration scenarios lockdown

Seven commits, seven test sets. v0 closes DEBT-051 and gives
operators an honest "is this attacker behaviourally stable, drifting,
or showing multiple operators?" surface — without crossing the
attribution-of-natural-persons bright line.

After v0, v1 (linkage / clustering) is gated on:
- v0 stable in production for ≥ 1 month
- ≥ 1 high-discrimination linkage signal calibrated
  (keystroke-dynamics simhash from BEHAVE-SHELL is the obvious
  candidate; v1 of the BEHAVE engine adds it post-step-10)

---

**Owner:** ANTI.
**Implementation gate:** this doc reviewed → Phase 1 starts after
`BEHAVE-INTEGRATION.md` v0 is live (observation table populated +
worker emitting `attacker.observation.*` events).
