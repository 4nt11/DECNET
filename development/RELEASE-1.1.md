# DECNET 1.1 — RAM / Process-Footprint Release

Predecessor: `v1.0.0`. Theme: cut the fleet resident set from **2.57 GB → target ~1.3 GB**
with near-zero risk, then optionally further via worker consolidation.

Analysis & measurements: see [improvements.md](improvements.md).

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
- [ ] **C2 — lazy topology re-export.** PEP 562 `__getattr__` in `topology/__init__.py`
      so `generate` loads on access, not on package import. Public API unchanged.
      Test: `import decnet.cli` must NOT pull `decnet.web.db.models`. Re-measure floor.
- [ ] **C3 — sweep remaining eager model pulls.** After C2, re-trace `import decnet.cli`;
      defer any other command module that drags the ORM in for registration only.
      Test: assert idle-worker floor stays under target.
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

## Projected

- C2–C3 (import floor): 2.57 GB → **~1.3 GB**. Nearly free.
- C4–C6 (consolidation): → **~0.9 GB**. Costs process isolation.
