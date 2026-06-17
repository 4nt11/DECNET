# DECNET 1.1 — RAM / Process-Footprint Release

Predecessor: `v1.0.0`. Theme: cut the fleet resident set from **2.57 GB → target ~1.0 GB**
by paying the import floor once per process-group instead of once per worker.

Analysis & measurements: see [improvements.md](improvements.md).

## ⚠️ Strategy correction (after C2 measurement)

Initial assumption: lazy imports would drop idle workers below the 86 MB floor → ~1.3 GB.
**Measurement disproved this.** All 25 CLI command modules transitively pull the SQLModel
ORM, and the 38 MB table chain is a *hub*: importing any one table loads the whole registry.
Most workers legitimately touch the DB, so they can't shed the ORM. Lazy registration only
helps the 2-3 genuinely **DB-less** workers (`forwarder`, `listener`, maybe `bus`).

**Therefore consolidation is the PRIMARY lever, not the fallback.** Paying the 86 MB floor
once for the idle herd (instead of ~8×) is the reliable ~600 MB win. C2/C3 stay as cheap
hygiene and to let the DB-less workers actually skip the ORM, but they are no longer the
headline.

## Why

18 long-running workers, ~2.57 GB resident. ~1.5 GB of that is the **same 86 MB import
floor paid 18×**, not workload. The floor is `import decnet.cli` pulling the entire
SQLModel ORM + all 26 model tables into every worker, even ones that never touch the DB.

## Root cause (pinned)

```
cli/__init__.py:22  from . import (... topology ...)
 → cli/topology.py:12        from decnet.topology.config import TopologyConfig
   → decnet/topology/__init__.py:10   from decnet.topology.generator import generate   ← TRIGGER
     → generator → allocator → repository → web.db.models.topology → all 26 tables (~38 MB)
```

The `topology/__init__.py` eager re-export of `generate` is the single thread that drags
the ORM into every worker. No production code imports `generate` from the package surface
(only tests, and they import the `compose` submodule) — safe to make lazy.

## Commit plan (incremental, one concern each)

- [x] **C1 — docs.** `improvements.md` (analysis) + this release plan.
- [x] **C2 — lazy topology re-export.** PEP 562 `__getattr__` in `topology/__init__.py`
      so `generate` loads on access, not on package import. Public API unchanged.
      Guard test added. *Finding: correct, but ORM pull is pervasive (see correction above)
      — C2 alone does not move the floor.*
- [ ] **C3 — DB-less worker lazy registration (reduced scope).** Confirm `forwarder` /
      `listener` (and audit `bus`) never touch models at runtime; make ONLY their command
      modules import-clean so those specific processes skip the 38 MB ORM. Skip the
      DB-touching majority — they can't shed it. Test: those modules don't pull
      `decnet.web.db.models`.
- [ ] **C4 — extract idle-herd coroutines.** Hoist the inline `_run()` closures
      (`webhook`, `canary`, `listener`, `forwarder`, `mutate`, `enrich`) into reusable
      `async def run(bus, cfg)` in their packages, so they're hostable by a supervisor.
      CLI commands become thin `asyncio.run(run(...))` wrappers. No behaviour change.
- [x] **C5 — `decnet supervise` primitive + batch group.** `decnet/supervisor.py`
      (per-worker restart loops, NOT TaskGroup) + `decnet supervise batch` hosting
      reconcile/enrich/orchestrate/mutate with one shared repo + `deploy/
      decnet-supervise-batch.service.j2` (Conflicts= the units it replaces). Unit-tested.
      **Live verification PENDING** — must be a controlled unit *swap* (stop the 4 units,
      start supervise-batch), never a parallel run: `mutate`/`orchestrate` are stateful and
      double-running mutates deckies / doubles synthetic traffic. Measure RSS before/after.
      Remaining groups (cpu, scapy) and webhook-timeout prerequisite not yet built.
- [ ] **C6 — merge scapy workers.** Optional. `collect`/`probe`/`sniffer` share the 76 MB
      scapy import once instead of 3×.

## Scope boundaries (no creep)

- **In:** import-floor reduction (C2–C3), idle-herd consolidation (C4–C5), scapy merge (C6).
- **Out:** `bus` (broker — stays alone), `api`/`web` (already multiprocess), `profiler`/`ttp`
  (heavy resident state + real CPU — stay separate). Not touching DB schema, bus wire format,
  or worker logic — only *where* code is imported and *which process* hosts it.

## Risk ladder

- C2–C3: import-site only, reversible, covered by an import-floor test. **Low.**
- C4: pure extraction, behaviour-preserving, existing tests guard it. **Low.**
- C5: introduces **shared fate** — one crash/OOM takes the herd; loses per-worker systemd
  restart + `MemoryMax`. **Medium.** Verify on the live fleet before adopting; keep the
  individual units as the fallback. Do C2–C4 first; C5 only if RAM still bites.

## C4/C5 Consolidation design — HOW, not just which

### The governing principle
**Consolidate by failure domain, keep every worker independently extractable.**
A worker's coroutine must not know whether it runs solo or hosted. "Hosted vs standalone"
is a *deploy-time config decision*, never a code fork. That single rule makes consolidation
reversible per-worker: if a co-located worker misbehaves, you pull it back to its own unit
by editing a config list — no code change, no redeploy of others.

### Two traps that kill the naive version

1. **`asyncio.TaskGroup` is the WRONG primitive.** Its semantics are all-or-nothing: if one
   task raises, the group cancels every sibling and propagates. That is the *opposite* of
   worker isolation. A bug in `webhook` would cancel `collector`. We need independent
   **supervision loops** — each worker wrapped in restart/backoff — gathered with
   `return_exceptions=True`, NOT a bare TaskGroup/gather.

2. **Consolidation silently discards systemd features we rely on.** Per-worker `Restart=`,
   `MemoryMax=` (cgroup), journal tagging, `After=`/`Requires=` ordering. The supervisor must
   *replace* the parts we used. `Restart=` → the in-process supervision loop below.
   `MemoryMax=` → survives as a **per-group** cgroup limit on the group's systemd unit (you
   lose per-*worker* granularity — that's the real cost, priced in below).

### The supervision primitive (the one reusable bit — ~12 lines, no framework)
```python
async def supervise(name, run, *, max_backoff=30):
    backoff = 1
    while not _shutdown.is_set():
        try:
            await run()                       # the worker's own coroutine
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("worker %s crashed; restart in %ds", name, backoff)
            await asyncio.sleep(backoff); backoff = min(backoff * 2, max_backoff)
        else:
            break
# host: await asyncio.gather(*(supervise(n, r) for n, r in group), return_exceptions=True)
```
This IS systemd `Restart=on-failure` with exponential backoff, in-process. Shutdown reuses
the existing `system.{worker}.control` bus topic.

### The decision axis: RAM ⟷ isolation (three coherent points)

| Design | RAM win | Isolation kept | Verdict |
|---|---|---|---|
| **A. Single supervisor** (whole herd, 1 proc) | max (−600 MB) | crash-isolation only (via loop); shared OOM, no per-worker cgroup | too blunt — one leak starves all |
| **B. Process groups by failure domain** ⭐ | ~−500 MB (4 floors vs ~13) | crash + group-level cgroup + reversible per-worker | **recommended start** |
| **C. Prefork master** (import once, `gc.freeze()`, fork children) | potentially max, real-process isolation | full per-process isolation via CoW-shared floor | **the big-win follow-on, gated on a 3.14 CoW measurement** |

### Recommended path: B now, measure C later

**Stage 1 — build the primitive + ONE group.** Ship `decnet supervise --group <name>` reading
a config list of `{worker: run-callable}`. Prove it on the safest group first.

**Group by failure domain AND co-residency** (corrected against the live `ps`):

`forwarder`/`listener` are role-split swarm singletons (forwarder=agent-side,
listener=master-side) — never co-resident with the herd, one per role, so consolidating them
saves nothing. They drop out of the grouping. The actually co-resident master herd is what
matters.

Bonus discovered during extraction: the batch workers all share the
`decnet.web.dependencies.repo` singleton → a group initializes it **once** and they share one
DB connection pool, not N. Savings beyond the import floor.

| Group (1 systemd unit each) | Workers | Why they belong together |
|---|---|---|
| `supervise-batch` ⭐ Stage 1 | `reconcile`, `enrich`, `orchestrate`, `mutate` | periodic/event DB loops, all share `repo`; low crash risk |
| `supervise-cpu` | `clusterer`, `campaign-clusterer`, `attribution`, `reuse-correlate` | bursty/reactive CPU; GIL OK while idle, offload heavy kernels to a shared `ProcessPoolExecutor` only if contention shows |
| `supervise-scapy` | `collect`, `probe` (+`sniffer` where present) | share the 76 MB scapy import once; tolerate blocking threads |

**Stay separate, no exceptions:** `bus` (broker), `api`/`web` (multiprocess by design),
`profiler` (353 MB) + `ttp` (308 MB) — big resident state + sustained CPU, co-location just
serializes them under the GIL. **Deferred standalone:** `webhook` (external HTTP → needs hard
timeouts before co-location), `canary` (self-manages its own repo; revisit).

Net on the master: idle/CPU/scapy herd (~10 procs) → **3 group procs**.

**Stage 3 — evaluate prefork (C).** Only if Stage 2's savings aren't enough. On Python 3.14,
immortal objects (PEP 683) + `gc.freeze()` before `fork()` keep module/code pages out of
refcount-dirtying, so CoW can share much of the 86 MB floor across *real* child processes —
full isolation AND the RAM win. But CoW decay is workload-dependent: **measure actual shared
RSS on 3.14 before committing.** If it shares well, prefork supersedes the groups; if refcounts
dirty the pages anyway, we keep B and stop.

### Why this order
B is incremental, reversible, and keeps the ops model you know — it de-risks the supervision
pattern on one group before betting the fleet. C is the higher ceiling but rests on an
empirical CoW question we haven't answered yet. Build the primitive once; it serves both.

## Projected (revised)

- C2–C3 (import floor): only the 2-3 DB-less workers shed the ORM. **~100 MB.** Cheap hygiene.
- **C4–C5 (consolidation): the main event.** Idle herd ~8 × 86 MB → 1 × 86 MB ≈ **−600 MB**.
- C6 (scapy merge): 3 × 76 MB → 1 × 76 MB ≈ **−150 MB**.
- Total: 2.57 GB → **~1.0 GB**. The bulk comes from consolidation, which costs isolation.
