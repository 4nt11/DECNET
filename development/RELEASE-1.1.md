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
- [ ] **C5 — `decnet supervise`.** TaskGroup supervisor hosting the idle herd in one
      process; reuses existing bus + `system.{worker}.control` shutdown. One systemd unit
      replacing ~8. `# ponytail: shared event loop — split a worker back out if it needs
      its own restart policy / MemoryMax`.
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

## Projected (revised)

- C2–C3 (import floor): only the 2-3 DB-less workers shed the ORM. **~100 MB.** Cheap hygiene.
- **C4–C5 (consolidation): the main event.** Idle herd ~8 × 86 MB → 1 × 86 MB ≈ **−600 MB**.
- C6 (scapy merge): 3 × 76 MB → 1 × 76 MB ≈ **−150 MB**.
- Total: 2.57 GB → **~1.0 GB**. The bulk comes from consolidation, which costs isolation.
