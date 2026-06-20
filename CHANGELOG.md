# Changelog

All notable changes to DECNET are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-06-20

OS fingerprint **cloak** — make a decky read as its claimed OS under *active*
fingerprinting (`nmap -O`), not just passively. sysctl profiles only reach global
packet fields; the cloak owns the SYN-ACK *shape* and stack *behaviours* sysctl
can't reach. Verified live: a `windows`/`windows_server` decky flips real
`nmap -O` from Linux to **Microsoft Windows / Windows Server 2012-2016**, with
client handshakes intact.

### Added
- `decnet.cloak` — egress TCP/IP masquerading library, run inside the decky base
  container (`python -m decnet.cloak`, `CAP_NET_ADMIN`/`CAP_NET_RAW`):
  - **NFQUEUE SYN-ACK mangler** — rewrites the TCP option order, advertised
    window, and IP-ID generation policy that sysctl cannot set per-container
    (preserves the kernel's live timestamp; recomputes `dataofs`/checksums).
  - **T2/T3 probe-response synthesizer** — answers the nmap probes Linux drops
    but Windows replies to (null-flags / SYN+FIN+PSH+URG to an open port).
  - Profiles live in `os_fingerprint.OS_MANGLE`, keyed by the same `nmap_os`
    slug; pure packet-shaping logic is unit-tested offline (scapy/netfilterqueue
    lazy-imported, Linux-only).
- `windows_server` nmap_os family — Windows Server stack deltas (ECN negotiated
  `CC=Y`, randomized IP-ID `TI=RD`); the `windows-server` and `domain-controller`
  archetypes now use it (workstation stays `windows`).
- Cloak base image (`templates/_shared/cloak/Dockerfile`, `FROM` the per-decky
  distro) and `deployer._sync_cloak_sources`, which ships the light `decnet`
  subtree into the build context. Base containers stay netns-safe — the cloak runs
  best-effort behind `exec sleep infinity`, so a cloak crash never tears down the
  decky or the netns its service containers share.

### Fixed
- **OS fingerprint timestamps bug**: the `windows` sysctl profile disabled TCP
  timestamps, fingerprinting as an ancient stack. Modern Windows 10/11 run
  timestamps **on** (`nmap SEQ.TS=A`) — corrected, and the single
  highest-weighted field in the nmap match.

## [1.2.0] - 2026-06-18

Prefork worker consolidation — share the import floor across *separate* processes
(own GIL, full isolation) via copy-on-write, for the heavy/isolation-critical
workers the in-process supervisor can't co-host.

### Added
- `decnet.prefork` — prefork supervisor primitive: a master imports the base
  floor once, then forks one child per worker (own process/GIL, CoW-shared
  floor), reaps and restarts with backoff, and shuts down gracefully. CoW
  viability measured on CPython 3.14 (idle child ~1 MB private, ~71 MB shared;
  `gc.freeze()` unnecessary thanks to PEP 683 immortal objects).
- `decnet fleet <name>` — prefork master that imports the shared base floor once
  then forks one child per worker. First fleet `heavy` = profiler + ttp (DB-only,
  process-isolated heavy tier); systemd unit `decnet-fleet-heavy.service`
  Conflicts= the units it replaces and carries no extra privilege.
  Verified live: fleet footprint ≈412 MB Pss (master 67 + profiler 81 + ttp 264)
  vs 661 MB standalone — profiler's RSS collapsed 353→110 MB (base floor now
  CoW-shared). ttp barely moved: its bulk is the privately-parsed ATT&CK bundle,
  which it alone consumes — so master-warming it was confirmed pointless and
  dropped. Lesson: prefork pays for base-floor-bound workers, not state-bound ones.
- **(Pro) Scan-based topology creation** — the MazeNET *New Topology* wizard
  gains a third option alongside Blank and Seed-based: import an Nmap XML scan
  and mirror its live hosts and services as decoys. Parses entirely in-browser
  (native `DOMParser`, no new dependency), resolves discovered service
  names/ports to DECNET services against the live catalog, groups hosts one LAN
  per /24, and builds the topology through the existing CRUD APIs (blank → LANs
  → deckies → edges) — no new backend. Hosts with no recognizable service
  (e.g. `nmap -sn`) default to a bare SSH decoy. The XML parser is hardened
  against XXE/SSRF and entity-expansion DoS, and scan values render as inert
  text (no XSS). Professional-tier; tree-shaken out of the community build
  (`decnet/pro` `v1.2.0`).

### Changed
- MITRE ATT&CK Enterprise bundle pinned 19.0 → **19.1**. The bundle and its
  LICENSE now resolve from `decnet/data/` (hash-pinned in `attack_version.py`,
  fetched on demand via `python -m decnet.ttp.attack_stix fetch`, gitignored —
  not committed).

### Removed
- Per-worker systemd unit templates superseded by consolidation:
  `decnet-{reconciler,enrich,orchestrator,mutator}` (→ `supervise batch`),
  `decnet-{clusterer,campaign-clusterer,attribution,reuse-correlator}`
  (→ `supervise cpu`), and `decnet-{profiler,ttp}` (→ `fleet heavy`).
  `decnet.target` now pulls in the 3 consolidated units. The underlying CLI
  commands remain for manual/standalone runs; a worker can be re-extracted to its
  own unit by editing the group/fleet spec.

## [1.1.1] - 2026-06-18

### Fixed
- Test suite: corrected 4 lifter clip tests that encoded the pre-ASVS
  `confidence_max` semantics (treating it as a `base × ceiling` multiplier).
  `confidence_max` is a true ceiling — `min(base, ceiling)` — since the ASVS
  hardening pass (BUG-8); the tests now assert the ceiling. They were masked by
  the `make test-web` ATT&CK-bundle fail-fast. No production code change.
- `test_topics_matches_documented_set`: added `attacker.fingerprinted` to the
  documented topic set — the TTP worker legitimately subscribes to it
  (JARM/HASSH/tcpfp/ipv6_leak fingerprint results feed TTP tagging).

## [1.1.0] - 2026-06-18

Worker consolidation: cut the long-running worker fleet's resident memory by
hosting co-resident workers in shared supervisor processes instead of one OS
process per worker. Behaviour-preserving — workers run the same code; only
*where* they are hosted changes, and any worker remains extractable back to its
own unit.

### Added
- `decnet supervise <group>` — hosts a co-resident worker group in one process,
  paying the Python import floor and the DB connection pool once instead of once
  per worker. Groups: `batch` and `cpu`.
- `decnet.supervisor` — in-process supervision primitive: each worker runs in its
  own restart loop with exponential backoff (in-process `Restart=on-failure`),
  run concurrently so one worker crashing never cancels its siblings.
  Deliberately not `asyncio.TaskGroup`, whose all-or-nothing cancellation would
  break worker isolation.
- `decnet.offload` — shared-pool CPU-kernel offload. The `cpu` group runs its two
  O(n²) connected-components kernels (`cluster_observations`, `cluster_identities`)
  in one shared `ProcessPoolExecutor` (forkserver) so they run in parallel
  instead of serialising under the GIL. Inline when no pool is installed, so
  standalone workers and tests are unchanged.
- systemd units `decnet-supervise-batch.service` and `decnet-supervise-cpu.service`
  (auto-rendered by `decnet init`); each `Conflicts=` the individual units it
  replaces, preventing accidental double-run.

### Changed
- `decnet.topology` no longer eagerly imports the topology generator (and the
  SQLModel ORM behind it) at package import. `generate` is now a lazy PEP 562
  re-export; the public API is unchanged.

### Performance
- **batch** group (`reconcile` + `enrich` + `orchestrate` + `mutate`):
  509 MB across 4 processes → **129 MB** in one. **−380 MB (75%)**, verified live.
- **cpu** group (`clusterer` + `campaign-clusterer` + `attribution` +
  `reuse-correlate`): 502 MB → **~146 MB** (incl. forkserver). **−357 MB (71%)**,
  verified live.
- Fleet total: **2.57 GB → ~1.83 GB (−737 MB)**.

### Notes
- `webhook` (external-HTTP egress; needs hard timeouts) and `canary` (manages its
  own repo) intentionally remain standalone for now.
- `bus`, `api`/`web`, `profiler`, and `ttp` remain separate by design (broker /
  multiprocess servers / heavy resident state + sustained CPU).

## [1.0.0] - 2026

Initial 1.0 release. See tag `v1.0.0`.

[1.2.0]: https://git.resacachile.cl/anti/DECNET/compare/v1.1.1...v1.2.0
[1.1.1]: https://git.resacachile.cl/anti/DECNET/compare/v1.1.0...v1.1.1
[1.1.0]: https://git.resacachile.cl/anti/DECNET/compare/v1.0.0...v1.1.0
[1.0.0]: https://git.resacachile.cl/anti/DECNET/releases/tag/v1.0.0
