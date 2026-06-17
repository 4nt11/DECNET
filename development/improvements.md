# DECNET RAM / Process-Footprint Improvements

Status: analysis complete, implementation not started.
Measured 2026-06-17 on the dev box, 18 live `decnet` workers, CPython 3.11 (`.311`).

## Headline

Fleet resident set ≈ **2.57 GB across 18 processes**. The bulk is not workload —
it is the same import floor paid 18 times over.

## Part A — the universal import tax (measured)

Every worker pays **~86 MB at startup before doing any work**:

```
interpreter            12 MB
+ import decnet.cli    74 MB   ← SQLModel/SQLAlchemy/Pydantic (~32MB)
                                 + EVERY decnet.web.db.models.* table
                                 + decnet.config + decnet.models
= floor                86 MB   paid 18× ≈ 1.5 GB of the 2.57 GB total
```

Measured cold, fresh interpreter each time (RSS):

| Layer | Resident | Who pays |
|---|---:|---|
| CPython interpreter | ~12 MB | everyone (shared COW) |
| `import decnet.cli` | +74 MB | **every worker** |
| └ SQLModel/SQLAlchemy/Pydantic | ~32 MB | the ORM chain |
| └ all `decnet.web.db.models.*` tables | ~20 MB | eagerly imported |
| `scapy.all` | +76 MB | only `collect`, `probe`, `sniffer` |

Confirmed NOT in the universal path:
- **scapy** — `scapy loaded after import decnet.cli? False`. Only the sniff/probe workers pay it.
- **pandas / numpy / sklearn** — no module-scope imports anywhere; already lazy-imported
  inside the functions that use them. Codebase got this right; leave it.

### Root cause

`decnet/cli/__init__.py:22-48` eagerly does `from . import (agent, api, ... ttp)` —
all 26 command modules imported at process start. Each pulls `decnet.config` +
`decnet.models` + the `decnet.web.db.models.*` chain at module top. So `decnet canary`
(which never touches TTP/swarm/webhook tables) still parses every table's SQLModel
metaclass.

importtime top offenders (pure model-table import cost, self time):
```
decnet.web.db.models.topology    21ms
decnet.web.db.models.attackers   15ms
decnet.models                    13ms
decnet.web.db.models.logs        11ms
... canary, ttp, swarm, auth, webhooks, orchestrator ...
```

## Part B — architecture map (for consolidation)

All 18 workers are **already asyncio coroutines subscribing to one shared UNIX-socket
bus** (`decnet/bus/`), with a `system.{worker}.control` shutdown topic already wired and a
`system.{worker}.health` heartbeat every 10s. They are already independent tasks — nothing
needs re-architecting, only re-hosting.

| Tier | Workers | Verdict |
|---|---|---|
| Broker | `bus` | Stays alone — it's the hub. |
| Already multiprocess by design | `api`/uvicorn, `web` (ThreadingTCPServer) | Leave them. |
| scapy + blocking sniff threads | `collect`, `probe`, `sniffer` | Keep out of main loop (76 MB scapy + GIL-thrashing threads). **Merge these 3** → pay scapy once. |
| Heavy resident state / CPU | `profiler` (353 MB), `ttp` (308 MB) | Keep separate — big live heaps, real CPU work; co-locating serializes them under GIL. |
| **The idle herd** ⭐ | `webhook`, `canary`, `listener`, `forwarder`, `mutate`, `orchestrator`, `reconciler`, `enrich`, + lighter clusterers | **The prize.** ~10 mostly-idle event-driven tasks each paying the 86 MB floor to `await` a bus event. Collapse into ONE supervisor. |

Loop-type evidence (from architecture map):

| Worker | Loop entry | Loop kind |
|---|---|---|
| bus | `cli/bus.py:10` → `bus/worker.py:44` | asyncio serve_forever + heartbeat |
| profiler | `cli/profiler.py:10` → `:33` | asyncio, 30s wakeup, batch 500 logs |
| ttp | `cli/ttp.py:46` → `:80` | asyncio queue pump on `attacker.observation.*` |
| clusterer | `cli/workers.py:260` → `:304` | bus-woken on `attacker.observed` |
| campaign-clusterer | `cli/workers.py:308` → `:362` | bus-woken on `identity.>` |
| web | `cli/web.py:27` → `:148` | ThreadingTCPServer.serve_forever (blocking) |
| api | `cli/api.py:18` → `:37` | subprocess.Popen uvicorn |

## Recommendation — ordered, stop when RAM is fine

### Step 1 — Lazy command registration (do first; safe, high-leverage)
Smallest diff, zero new failure modes, helps with or without consolidation. Typer only
needs a module imported to *run* a command, not to *register* it. Defer the
`from . import (...)` so `decnet canary` loads canary's deps only, not all 26 tables.
Reversible. Expected: idle workers drop well below the 86 MB floor.

### Step 2 — Consolidate the idle herd (only if RAM still bites after step 1)
`decnet supervise` runs the idle event-driven workers as tasks in ONE process — pay the
floor 1× instead of ~10×. Plumbing already exists; the supervisor is ~10 lines:

```python
async with asyncio.TaskGroup() as tg:
    for w in IDLE_WORKERS:
        tg.create_task(w.run(bus))   # each already a bus-subscribed coroutine
```

**Cost to weigh:** consolidation trades RAM for **shared fate** — one crash takes down
~10 workers, one OOM kills the herd, and you lose per-worker systemd restart policy and
`MemoryMax=` caps. That's why step 1 comes first: free safety, and may make step 2
unnecessary.

### Step 3 — Merge the 3 scapy workers
Share the 76 MB scapy import once instead of 3×.

### Projected trajectory
- 2.57 GB → **~1.3 GB** from lazy imports alone (nearly free)
- → **~0.9 GB** if also consolidating the herd + merging scapy (costs isolation)

The first 1.3 GB is nearly free; the last 400 MB costs you process isolation.
