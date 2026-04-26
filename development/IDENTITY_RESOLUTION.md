# Identity Resolution — Design

**Status:** pre-implementation. This doc is the spec; code follows.

**Roadmap pressure:** Campaign Clustering (`CAMPAIGN_CLUSTERING.md`),
Keystroke Dynamics (`DEVELOPMENT_V2.md` §1), Federation
(`DEVELOPMENT_V2.md` §3).

## Premise

The `attackers` table is keyed per-IP — one row every time we observe
activity from a new source IP. That works for naive scoring, but it
conflates two distinct concepts:

- **Observation event.** "We saw activity from IP X starting at T1."
  Mutable; IPs come and go; the unit of *ingestion* on the wire.
- **Actor identity.** "These N observations are the same hands."
  Semi-stable; recovered from signals the attacker can't cheaply rotate
  (JA3, HASSH, payload hashes, C2 callbacks, eventually keystroke
  rhythm).

A campaign is then one-level-up: "these M identities are coordinated."
The clean ladder is **Observation → Identity → Campaign**, three
levels, each derived from the level below by clustering on
increasingly meta signals.

We will not ship a clusterer in this PR sequence. The plan here is the
**substrate the clusterer writes into** — schema, API, bus topics,
frontend hooks — landed empty so downstream work targets a stable
shape and the campaign clustering fixtures can encode honest
multi-row-per-actor scenarios.

Order of work, strictly:

1. This design doc.
2. Schema-only PR — `attacker_identities` table + nullable
   `attackers.identity_id` FK. Empty table, no production reads/writes.
3. Read-only API — `/api/v1/identities/*` returning empty lists / 404.
4. Frontend — conditional `IdentityDetail` page; `AttackerDetail`
   gains a "Identity: <link>" badge when populated.
5. Bus topics + wiki — declare topics, document, no publishers yet.
6. Test factory adapter — campaign factory emits N rows per
   IP-rotating actor with shared `truth_identity_id`. Unblocks
   fixture 2 (`vpn_hopping`) and beyond.

The clusterer itself follows after fixtures 2–6 ship, on the
substrate this PR sequence builds.

---

## Why now, why not later

**Pre-v1 schema changes are nearly free.** SQLModel
`metadata.create_all()` picks up new tables; new nullable columns are
free; no Alembic until v1. Real production data is currently small
and replayable.

**Post-v1 the cost compounds.** Real attacker rows accumulate, FKs
proliferate, dashboard URLs get bookmarked, federation gossip locks
in `schema_version=1` payload shapes. Every month we wait, the
migration becomes harder.

**V2 keystroke dynamics needs an identity row.** `kd_digraph_simhash`
correlation is *the* feature that graduates fingerprint into identity.
It needs a row to attach to. Without it, the V2 work either rebuilds
this substrate from scratch, or hangs simhash off the per-IP
observation table — which means an IP-rotating actor's typing rhythm
gets fragmented across every IP they used.

**Federation gossip is identity-level.** Operators in different
geographies will never share an IP. They may share an identity.

---

## Why sibling-add, not rename

**Considered:** rename `attackers` → `attacker_observations`.
Eliminates the "attacker means observation" lie at the schema layer.

**Rejected.** Costs:

- 126 occurrences of `attacker_uuid` across the codebase, mid-migration
  churn directly on top of DEBT-041 (commit `3eb67c9`, just landed).
- Frontend `Attacker` → `Observation` mismatches user mental model.
  Operators click "show me the attacker," not "show me the
  observation." Splunk, ELK, MISP, every CTI platform keeps the
  user-facing concept stable and exposes identity resolution as a
  derived view.
- The lie is in *documentation*, not in code. Code already operates
  per-IP correctly; it's just named imprecisely. Fixing it via
  docstring + wiki is far cheaper than renaming.

**Adopted:** **sibling-add.** Keep the `attackers` table; document its
semantic role as "per-IP observation." Add `attacker_identities` as a
new sibling. Add nullable `attackers.identity_id` FK. The clusterer
populates identities. Existing code paths are unchanged. Frontend
`AttackerDetail` gains a conditional widget; new `IdentityDetail`
page aggregates observations.

The "Attacker" vocabulary continues to mean "what the operator clicks
in the dashboard" — the per-IP observation row. "Identity" is the
analyst-facing concept, surfaced when the clusterer has resolved one.

---

## Schema

### `AttackerIdentity` (new)

| Column | Type | Notes |
|---|---|---|
| `uuid` | TEXT PK | uuid4(); identities are NOT fingerprint-derived (fingerprints evolve as the actor's tooling changes; the row's identity must outlive its current fingerprints) |
| `schema_version` | INT, default 1 | Federation-gossip compat from day one. Bumping feature definitions without a version field silently poisons other operators' clustering |
| `campaign_id` | TEXT FK nullable | Set by the campaign clusterer (downstream effort) |
| `first_seen_at` | TIMESTAMP | Earliest observation linked to this identity |
| `last_seen_at` | TIMESTAMP | Latest observation linked to this identity |
| `created_at` / `updated_at` | TIMESTAMP | Row audit |
| `confidence` | REAL nullable | Identity-cohesion score from clusterer; null until clusterer writes |
| `observation_count` | INT default 0 | Denormalized for cheap dashboard reads. Maintained by the clusterer when it links/unlinks |
| `ja3_hashes` | TEXT (JSON list) nullable | Multiple TLS stacks per actor possible (different tools, different hosts) |
| `hassh_hashes` | TEXT (JSON list) nullable | |
| `payload_simhashes` | TEXT (JSON list) nullable | 64-bit ints serialized as hex strings |
| `c2_endpoints` | TEXT (JSON list) nullable | Domain or IP, dedup'd |
| `kd_digraph_simhash` | BINARY(8) nullable | V2 keystroke-dynamics hook. Same shape as `SessionProfile.kd_digraph_simhash`; identity-level value is the centroid (or majority vote) across the identity's sessions |
| `merged_into_uuid` | TEXT self-FK nullable | Soft-merge audit trail. When the clusterer combines two existing identities, the loser's row stays in place with `merged_into_uuid` pointing at the winner — preserves the audit trail without orphaning FKs |
| `notes` | TEXT nullable | Operator-editable. Free-form |

All clusterer-populated fields are nullable; the table ships empty and
is valid in that state.

### `attackers` (extended)

One nullable column added:

| Column | Type | Notes |
|---|---|---|
| `identity_id` | TEXT FK nullable, indexed | References `attacker_identities.uuid`. NULL until the clusterer resolves an identity |

**Migration:** None needed. Pre-v1 SQLModel `metadata.create_all()`
adds the new table and column. No data backfill (column is nullable).

---

## Where intel lives — both, with clear semantics

DEBT-041 (`3eb67c9`) just re-keyed `attacker_intel` on `attacker_uuid`
(observation level). That work is correct; we do **not** touch it
here.

**Observation-level intel** (`attacker_intel`, current):
- AbuseIPDB confidence, GreyNoise classification, abuse.ch matches,
  PTR records, GeoIP — all **IP-scoped facts**. An identity spanning
  40 IPs has 40 distinct AbuseIPDB verdicts. We must not lose that
  granularity.

**Identity-level intel** (`attacker_identity_intel`, deferred):
- Aggregate reputation (e.g. "this identity has been reported as
  malicious across 4 of 5 observed IPs").
- Threat-actor naming from MISP/CTI feeds, where naming is
  actor-scoped not IP-scoped.
- TTP / MITRE ATT&CK tags.

Different lifecycle (clusterer-driven, not enricher-driven), different
inputs (aggregates over observations, not direct API calls), so it
gets its own table and its own enricher when it ships. **Not in this
PR sequence.**

The IdentityDetail API (read side) aggregates observation intel on
read until the identity-level table exists.

---

## Bus Topics

Three new topics. No publishers in this PR sequence — constants exist;
publishers ship with the clusterer.

| Topic | Payload | When |
|---|---|---|
| `identity.formed` | `{identity_uuid, observation_uuids: [], confidence, first_seen_at}` | Clusterer creates a new identity from one or more observations |
| `identity.observation.linked` | `{identity_uuid, observation_uuid, confidence_after}` | Clusterer attaches an observation to an existing identity (or re-attaches one previously linked elsewhere) |
| `identity.merged` | `{winner_uuid, loser_uuid, observation_uuids: [], confidence_after}` | Clusterer collapses two identities. The loser's row stays in place via `merged_into_uuid`; subscribers re-key any cached identity references to the winner |

**Deferred:** `identity.campaign.assigned`. Adds opportunistically
when the campaign clusterer ships. YAGNI before then.

**Wiki:** `Service-Bus.md` documents these in the same commit that
adds the constants (per the project's `feedback_wiki_bus_signals`
rule).

---

## API Surface

All new endpoints are read-only and auth-gated identically to
`/api/v1/attackers/*` (per `project_health_auth_gated`).

| Method | Path | Returns |
|---|---|---|
| GET | `/api/v1/identities` | Paginated list of identities. Response shape mirrors `AttackersResponse` |
| GET | `/api/v1/identities/{uuid}` | Identity row + aggregated intel summary (rolled up from FK'd observations) + campaign stub if assigned |
| GET | `/api/v1/identities/{uuid}/observations` | Paginated list of `Attacker` observation rows that FK to this identity |

While the table is empty, every endpoint returns either an empty list
or 404 — both are valid responses.

**`AttackerDetail` change** (frontend, not API): when
`attackers.identity_id` is non-null, render a "Identity: <uuid-link>"
badge linking to `/identities/<uuid>`. No change otherwise.

---

## Frontend

- **`AttackerDetail.tsx`** — conditional badge. Zero behavior change
  when `identity_id` is null.
- **`IdentityDetail.tsx`** (new) — aggregates observations, fingerprint
  summary, intel summary, campaign link. Same visual vocabulary as
  `AttackerDetail` so operators feel at home.
- **Routing** — `/identities/:uuid` alongside `/attackers/:uuid`.
- Default browse remains "Attackers." There is no "Identities" tab
  in the main navigation until identities are populated; once they
  are, an "Identity Resolution" entry appears under the Analytics
  section (this is post-clusterer; out of scope here).

---

## Risks

1. **Confidence drift.** The clusterer can rewrite identity
   assignments as evidence accumulates. An observation linked to
   identity-A today may move to identity-B tomorrow. UI must surface
   this without alarming operators ("This observation has been
   re-attributed; previous identity remains as a soft-merged
   reference"). The `merged_into_uuid` chain is the audit trail.

2. **API URL stability.** Identity UUIDs that get soft-merged via
   `merged_into_uuid` should still resolve at
   `/api/v1/identities/{uuid}` — return 301 to the winner, or return
   the loser row with a `merged_into` link. Decide before the
   clusterer ships.

3. **Schema-version lock-in for federation.** `schema_version=1` is
   what we ship. Any fingerprint added to the identity row post-v1
   bumps the version. Operators behind by versions get a degraded
   gossip experience but should not crash — the receiver must
   tolerate unknown fields.

4. **Observation FK proliferation.** Today only `attackers` would
   carry `identity_id`. Tomorrow, `SessionProfile`, `AttackerIntel`,
   webhook payloads might want it too. Resist proliferation; the
   normalised path is `observation.identity_id` and identity-level
   facts go in `attacker_identity_intel`. We only carry `identity_id`
   on tables where joining via the observation row is materially
   slower at read time.

5. **Identity-level intel scope creep.** Easy to start moving DEBT-041
   intel up to identity level "for cleanliness." Don't. AbuseIPDB
   results are IP-scoped facts; moving them up loses information.
   Identity-level intel is *aggregate* intel, a different thing.

---

## Open Questions

1. **Revocability of identity merges.** When the clusterer merges
   identities A and B into A (via `merged_into_uuid`), can a future
   evidence update split them back apart? Leaning yes — clear
   `B.merged_into_uuid`, re-link B's original observations. But that
   leaks history (any subscriber that cached "B is gone" now sees B
   alive again). May need an explicit `identity.unmerged` topic.
   Decide before the clusterer ships.

2. **`AttackerDetail` UX when `identity_id` changes.** If an operator
   has a tab open showing `attackers/X` with identity_id=A, and the
   clusterer rewrites it to identity_id=B, the page goes stale.
   Acceptable: stale tab, refresh on focus. Better: SSE channel
   pushes the change. Decide alongside the clusterer.

3. **`SessionProfile.identity_id` FK.** Does this PR sequence add it,
   or does it wait for V2 keystroke dynamics? Leaning **wait** — the
   FK is only useful when the identity-level keystroke similarity
   query exists, which is V2 work. Adds a column we don't read in
   v1 = unused complexity.

4. **Webhook payload identity_id.** Adds opportunistically once
   identities are populated. Not load-bearing for this PR sequence.

5. **Identity-level intel table.** Schema sketch is straightforward
   (uuid PK, identity_uuid FK, source, confidence, ttps JSON,
   timestamps), but the enricher is meaningfully different from
   the IP-scoped one. Defer entirely.

---

## What is explicitly NOT in this design

- The clusterer worker (`decnet/clustering/` worker bin). Designed in
  `CAMPAIGN_CLUSTERING.md` §4; lands on top of this substrate.
- `attacker_identity_intel` table.
- `SessionProfile.identity_id` FK.
- Webhook payload `identity_id` enrichment.
- Renaming `attackers` → `attacker_observations`. Considered, rejected.
- Identity-level federation gossip. The schema is federation-ready
  (schema_version, no operator-identifying fields); the gossip wire
  itself is V2.

---

## Verification

After all 5 commits below land:

```bash
source .311/bin/activate

# Schema lands cleanly.
pytest tests/db/test_identity_schema.py -v

# API surface returns expected shapes against an empty identities table.
pytest tests/web/test_api_identities.py -v

# No regressions on the unchanged path.
pytest tests/web/ tests/profiler/ tests/correlation/ -v

# Bus topic constants importable; wiki updated.
python -c "from decnet.bus.topics import IDENTITY_FORMED, IDENTITY_OBSERVATION_LINKED, IDENTITY_MERGED; print('OK')"
test -f wiki-checkout/Identity-Resolution.md
grep -q "identity.formed" wiki-checkout/Service-Bus.md

# Factory adapter unblocks fixture 2.
pytest tests/clustering/test_campaign_factory.py -v
```

Manual smoke after schema + API + frontend:

- `decnet api` then `decnet web`.
- Browse to an existing AttackerDetail page → no badge (identity_id is NULL).
- `GET /api/v1/identities` → `{"data": [], "total": 0, ...}`.
- `GET /api/v1/identities/<random-uuid>` → 404.
