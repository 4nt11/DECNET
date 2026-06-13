# ADR-001 — Fleet Source of Truth

- **Status:** PROPOSED (discussion — not yet accepted)
- **Date:** 2026-06-12
- **Context owner:** ANTI
- **Drives fix for:** BUG-2 (destructive fleet-replace / silent wipe), see `QA_REPORT.md`

---

## 1. Context

DECNET currently keeps the deployed-fleet inventory in **two unsynchronized stores**:

| Store | Read by | Written by |
|-------|---------|------------|
| `decnet-state.json` file (`load_state()`) | `repo.get_deckies()` → the UI fleet view, collision pre-checks | CLI/engine path (`engine.deployer.save_state`), `decnet status`, sniffer, collector |
| DB `State` table, key `"deployment"` (`repo.get_state`/`set_state`) | the web deploy handler's `existing_deckies` snapshot | **only** the web deploy handler |

The web is a **non-dependency**: the same deploys can be driven entirely from the CLI, and CLI state lives in `decnet-state.json`. Because the two stores never reconcile, a fleet established via CLI/seed is invisible to the web deploy handler's collision guard.

### BUG-2 failure chain (source-traced)

1. CLI/seed establishes a fleet → written to `decnet-state.json`, **never** to DB `"deployment"`.
2. UI reads `get_deckies()` (JSON) → shows decky-02/03 correctly.
3. Wizard POSTs a new decky-04 with `replace_fleet=false`.
4. Handler reads `existing_deckies` from `repo.get_state("deployment")` → **None** → `existing_deckies = []`.
5. Collision guard compares against `[]` → no conflict → `config.deckies = [] + [decky-04]`.
6. `run_deploy` → `LocalDeployStrategy` → `engine.deployer.deploy(config)`:
   - `write_compose(config, COMPOSE_FILE)` writes a compose file containing **only decky-04** (`deployer.py:681`).
   - `_compose("down", "--remove-orphans", …)` (`deployer.py:708`) tears down the whole compose project, then `up` brings back only decky-04.
   - `_mirror_fleet_teardown_to_db` drops the survivors' rows.
7. Result: fleet silently wiped to one decky. HTTP 202. No warning.

**Key trap:** the destructive call is `deployer.py:708` (`down --remove-orphans` against a compose file rewritten from `config.deckies`). Any source-of-truth fix that does not also guarantee `config.deckies` is the **complete** desired fleet before `write_compose` leaves BUG-2 alive.

---

## 2. What the UI actually consumes

`DeckyConfig` (`decnet/models.py:87`) full field set:

```
name, ip, services[], distro, base_image, build_base, hostname,
archetype, service_config{}, nmap_os, mutate_interval, last_mutated,
last_login_attempt, host_uuid
```

Frontend `Decky` type (`DeckyFleet/types.ts`) + what is **rendered/edited**:

| Field | Displayed? | Where |
|-------|-----------|-------|
| name, ip, services | yes | DeckyCard / InspectPanel |
| hostname, distro, archetype | yes | DeckyInspectPanel:77-79 |
| mutate_interval, last_mutated | yes | DeckyInspectPanel:80-81 |
| **service_config** | **yes — EDITED** | DeckyCard:322 (per-service config editor `currentConfig`) |
| base_image, build_base, nmap_os, last_login_attempt | no | — |

**Conclusion:** `service_config` is not just stored — it is rendered and **edited** in the UI. A "minimal scalar labels" scheme (name/ip/services only) would amputate editable state. Fidelity requires carrying the full `DeckyConfig`.

---

## 3. Options

### Option A — API reads only the DB; ignore `decnet-state.json` (web side)

Align `get_deckies()` and the deploy handler both on DB `"deployment"`. The web becomes a self-contained plane on the DB; CLI stays on the JSON file. The two planes are explicitly **non-interoperable**.

- **Pros:** smallest change; closes the desync *within the web plane*.
- **Cons:** ANTI's own verdict — "honestly the incorrect way of doing things." Two planes that can't see each other is a design smell, not a fix. A CLI-seeded fleet is still invisible to the web (and vice-versa); the wizard would still drive a reconciler that tears down CLI containers it can't see. Does **not** fix the cross-plane wipe, only the intra-web one.

### Option B — Docker container labels as source of truth (ANTI's proposal)

Stamp every DECNET container with provenance + identity labels; reconstruct the fleet by querying Docker. `decnet-state.json` degrades to a CLI-side convenience cache, no longer authoritative.

Proposed labels:
```
com.decnet.host        = "true"          # selector for "this is a DECNET decky"
com.decnet.deploy_type = "api" | "cli"   # provenance, NOT a partition
com.decnet.service     = "<service>"     # or the broader identity
com.decnet.config      = "<DeckyConfig JSON>"  # REQUIRED to preserve service_config fidelity (see §2)
```

Fleet read becomes `docker ps --filter label=com.decnet.host=true` (+ `-a` for stopped), then deserialize `com.decnet.config`.

- **Pros:**
  - **One source of truth = reality.** The collision guard and the reconciler read the SAME state, so BUG-2 cannot recur.
  - Survives a DECNET process restart (Docker keeps running; labels persist on the real object).
  - `deploy_type` makes the "two planes" distinction unnecessary — one fleet, labeled by origin. The guard queries ALL `com.decnet.host=true` regardless of origin, so it can never blind-wipe a CLI decky.
  - This is the orchestrator-standard pattern (label the real object, reconcile against it).
- **Cons / constraints:**
  - **Swarm.** The master cannot `docker ps` a remote worker. Remote deckies STILL need a registry → keep `decky_shards` (DB, heartbeat-driven). Honest model is **hybrid**: local truth = labels, remote truth = `decky_shards`.
  - **Fleet-global config** (`interface, subnet, gateway, ipvlan, mutate_interval, log_file, compose_path`) is not per-container. Proposed home: **labels on the macvlan/ipvlan network object** (exactly one, DECNET-owned, correct scope). NOT replicated onto every container.
  - **Label payload.** Preserving `service_config` fidelity forces a `com.decnet.config` JSON blob. Works (label values are generous) but it is config-in-label-land, with its own serialization discipline.
  - **Performance.** `/deckies` is UI-polled and load-tested. Querying Docker on every read is heavier than a file/DB read. Mitigation: the existing 5s TTL cache (`api_get_deckies.py:_DECKIES_TTL`) extends naturally over the Docker query.
  - **Does NOT by itself fix `deployer.py:708`.** Labels give the DATA to build the COMPLETE config (live + new) before `write_compose`; the merge must actually be done. Labels make the correct merge possible; they don't perform it.

### Option C — Single DB store as canonical (both web and CLI write DB)

Make the CLI write the DB `"deployment"` key too; retire `decnet-state.json` as authority. One store, but it's bookkeeping, not reality — can still drift from actual containers on crash/manual `docker rm`.

- **Pros:** single store; no Docker-query perf cost; swarm-friendly (DB is already the remote registry).
- **Cons:** reintroduces the "trust the ledger, not reality" fragility that Option B specifically escapes; CLI now hard-depends on the DB being reachable, eroding the web-is-a-non-dependency property.

---

## 4. Recommendation (for discussion)

**Option B (labels), accepted as a hybrid:** local fleet truth = Docker labels; remote fleet truth = `decky_shards` (DB); fleet-global config = network-object labels; `decnet-state.json` demoted to CLI convenience cache.

Mandatory companion change regardless of option chosen: **build the complete desired `config.deckies` (surviving live fleet + new submissions) before `write_compose`/`deployer.py:708`**, so `down --remove-orphans` + `up` is a no-op on survivors. This is the actual teardown fix; the source-of-truth choice only determines *where the survivor list is read from*.

---

## 5. Open questions (resolve before cutting code)

1. **`com.decnet.config` blob vs. exploded scalar labels** — do we accept one JSON label for fidelity, or split into N labels and reconstruct? (Fidelity for `service_config` pushes toward the blob.)
2. **Global config home** — network-object labels confirmed as the home, or a single sentinel "fleet" container/label set?
3. **Swarm boundary** — is the local-labels / remote-`decky_shards` split acceptable, or do we want labels mirrored back to the master via heartbeat for a uniform read path?
4. **Stopped/failed containers** — does `-a` (include stopped) count toward the fleet for collision purposes, and how do we represent non-running status the JSON file never tracked?
5. **Migration** — first label-aware deploy after upgrade: how do we adopt already-running unlabeled containers (relabel in place vs. require one redeploy)?
6. **`decnet-state.json` final role** — pure CLI cache, or removed entirely with CLI also reading labels?

---

## 6. Affected files (for whichever option lands)

- `decnet/web/router/fleet/api_deploy_deckies.py` — `existing_deckies` snapshot (lines 48, 84), collision guard (124-145), `set_state("deployment")` (194)
- `decnet/web/router/fleet/api_get_deckies.py` — `get_deckies` read path + TTL cache
- `decnet/web/db/sqlmodel_repo/__init__.py:174` — `get_deckies()` (currently `load_state()`)
- `decnet/engine/deployer.py:681` (`write_compose`), `:708` (`down --remove-orphans`), `:571`/`:623` (`_mirror_fleet_*`)
- `decnet/config.py` — `save_state`/`load_state`, `STATE_FILE`
- `decnet/lifecycle/runner.py` / `strategies.py` — `LocalDeployStrategy` → `deployer.deploy`
- `decnet/models.py:87` — `DeckyConfig` (label serialization surface)

---

## 7. CORRECTION (source-traced 2026-06-12) — the store topology is wider than §1 said

§1's claim that DB `State["deployment"]` is *"written only by the web deploy handler"* is **WRONG**. A grep for its readers/writers shows it is the shared coordination store for the **entire web + mutator plane**:

| Site | Op |
|------|----|
| `api_deploy_deckies.py:48,194` | read + write |
| `api_mutate_decky.py:55,76` | read + write |
| `api_mutate_interval.py:32,45` | read + write |
| `swarm_mgmt/api_list_deckies.py:28` | read |
| `mutator/engine.py:84,126,189,413` | read + write (autonomous mutator) |

Consequences:
- A one-line "deploy handler reads `load_state()`" swap makes deploy **diverge from its own plane** (mutate handlers + the background mutator still read the DB key). Lateral move, not a fix. **Empirically confirmed:** that edit broke 4/5 tests in `tests/api/fleet/test_deploy_additive.py` (the survivor was `replace_fleet=True`, the only case that doesn't read the prior fleet), because under `DECNET_CONTRACT_TEST` the deploy task is skipped so `save_state` never writes the JSON, and the handler couldn't see its own prior `set_state` write. Read-one-store / write-another is self-inconsistent.
- Pointing `get_deckies()` at the DB key **also fails to fix BUG-2**: a CLI-seeded fleet isn't in `State["deployment"]` either (CLI writes JSON + `fleet_deckies`), so the reconcile-against-incomplete-inventory wipe survives.

### The model the codebase ALREADY documents (`fleet/reconciler.py:1-29`)

```
1. decnet-state.json — canonical for offline / no-API consumers (CLI, status, sniffer, collector)
2. fleet_deckies table — "what the orchestrator, web dashboard, and REST API see"
3. docker inspect — actual per-container runtime state
Resolution: JSON-only → INSERT; DB-only(this host) → DELETE; both → state := docker-aggregated.
```

Two facts this hands us:
1. **The API was DESIGNED to read `fleet_deckies`** — the engine-mirrored table written on *every* deploy/teardown regardless of origin (`deployer.py:571 _mirror_fleet_deploy_to_db`, `:623` teardown). The live deploy/collision-guard code reading `State["deployment"]`, and `get_deckies()` reading the JSON file, are both **drift from the documented design**. `fleet_deckies` is the cross-plane store that *does* contain a CLI-seeded fleet.
2. **Docker is already the ultimate authority** — the reconciler converges JSON and DB *to docker-aggregated state*. ANTI's label proposal (Option B) is not a new paradigm; it promotes docker from reconciler-tiebreaker to primary read path.

### Revised recommendation

Two viable directions, both grounded in the existing design rather than a new store:

- **B′ (labels / docker-primary)** — the ADR's Option B, now understood as *promoting* the reconciler's existing docker-authoritative tiebreaker to the primary fleet read. Strongest long-term; same swarm caveat (remote = `decky_shards`/`fleet_deckies`, master can't `docker ps` workers).
- **D (converge on `fleet_deckies` now)** — make the deploy collision-guard AND `get_deckies()` read `fleet_deckies` (`list_fleet_deckies` / `list_running_fleet_deckies`), the store the design already names as the API's view. Smaller than relabelling; immediately closes the CLI-invisible-to-web gap because `fleet_deckies` is engine-mirrored on CLI deploys too. The mutate handlers + mutator engine reading `State["deployment"]` become the next consolidation target.

**Unchanged hard constraint:** whichever store wins, the handler must still build the COMPLETE desired `config.deckies` (survivors + new) before `write_compose`/`deployer.py:708`. The store choice only decides where "survivors" is read from.

### Open question added to §5

7. **`State["deployment"]` vs `fleet_deckies`** — do we converge the whole web+mutator plane onto `fleet_deckies` (Option D), or go straight to docker-primary (Option B′) and let `fleet_deckies` be the swarm/remote registry? The mutator engine (`mutator/engine.py`) is the heaviest consumer of `State["deployment"]` and must move in lockstep.
