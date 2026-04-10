# OS Fingerprint Spoofing — Hardening Roadmap

This document describes the current state of OS fingerprint spoofing in DECNET
and the planned improvements to make `nmap -O`, `p0f`, and similar passive/active
scanners see the intended OS rather than a generic Linux kernel.

---

## Current State

OS spoofing is partially implemented. Each archetype declares an `nmap_os` slug
(e.g. `"windows"`, `"linux"`, `"embedded"`). The **composer** resolves that slug
via `os_fingerprint.get_os_sysctls()` and injects the resulting kernel parameters
into the **base container** as Docker `sysctls`. Service containers inherit the
same network namespace via `network_mode: "service:<base>"` and therefore appear
identical to outside scanners.

### Currently tuned knobs

| Sysctl | Purpose |
|---|---|
| `net.ipv4.ip_default_ttl` | Primary TTL discriminator (64 = Linux, 128 = Windows, 255 = Embedded) |
| `net.ipv4.tcp_syn_retries` | SYN retransmit count before giving up |

### What this fools

| Scanner probe | Status |
|---|---|
| ping TTL | ✅ Fully spoofed |
| TCP SYN retry count | ✅ Tuned |
| `nmap -O` OS family (Win vs Linux) | ⚠️ Partial — likely correct family, wrong version |
| `p0f` passive fingerprint | ⚠️ Partial — TTL correct, window/options wrong |
| Full `nmap -O` version/build match | ❌ Not achievable without deeper tuning |

---

## Improvement Phases

### Phase 1 — Extended Sysctls (Low effort, High impact)

Several additional sysctls are **network-namespace-scoped** and can be safely set
per-container without `--privileged`. These directly affect nmap's SEQ, OPS, and
WIN probe groups.

**Changes required:** extend `OS_SYSCTLS` in `decnet/os_fingerprint.py`.

| Sysctl | nmap probe group | Windows | Linux | Embedded |
|---|---|---|---|---|
| `net.ipv4.tcp_timestamps` | SEQ/OPS — timestamp option presence | `0` | `1` | `0` |
| `net.ipv4.tcp_window_scaling` | WIN — window scale option | `1` | `1` | `0` |
| `net.ipv4.tcp_sack` | OPS — SACK permitted option | `1` | `1` | `0` |
| `net.ipv4.tcp_ecn` | ECN probe — explicit congestion notification | `0` | `2` | `0` |
| `net.ipv4.ip_no_pmtu_disc` | IE — DF bit copying in ICMP replies | `0` | `0` | `1` |
| `net.ipv4.tcp_fin_timeout` | T2–T6 — FIN_WAIT duration | `30` | `60` | `15` |

> **Highest single-value impact:** setting `net.ipv4.tcp_timestamps = 0` for
> Windows is the strongest signal. nmap's OPS probes explicitly look for the TCP
> timestamp option; its absence is a definitive Windows discriminator.

**Expected result after Phase 1:** `nmap -O` correctly identifies OS family in
the vast majority of scans. `p0f` passive fingerprinting becomes significantly
more convincing.

---

### Phase 2 — TCP Window Size Mangling (Medium effort, Very high impact)

nmap's WIN probes record the raw **TCP window size** in SYN-ACK replies. This
is the single most discriminating feature after TTL. It cannot be set with
per-namespace sysctls because `net.core.rmem_default` is global.

The fix is an **iptables rule applied at base container startup** via a custom
entrypoint script.

#### Target window sizes by OS

| OS | TCP Window Size | Notes |
|---|---|---|
| Windows 10 / 11 | `64240` | Most common modern value |
| Windows 7 / Server 2008 | `8192` | Classic Windows signature |
| Linux 5.x / 6.x | `29200` | Default `tcp_rmem` min/4 |
| Linux 4.x | `43690` | Older default |
| FreeBSD / macOS | `65535` | BSD signature |
| Embedded / Cisco | `4128`–`8760` | Varies widely |

#### Implementation sketch

Add a parameterized entrypoint script (`templates/base/entrypoint.sh`) that
receives the target window size as an environment variable and applies an
`iptables` MANGLE rule before yielding to `sleep infinity`:

```bash
#!/bin/sh
# Apply TCP window size spoofing via iptables mangle
if [ -n "$SPOOF_TCP_WINDOW" ]; then
    iptables -t mangle -A POSTROUTING -p tcp \
        -j TCPMSS --set-mss 1460
    # Clamp outgoing window to the target value
    # Requires xt_TCPMSS kernel module on the host
fi
exec sleep infinity
```

The composer would inject `SPOOF_TCP_WINDOW` as an environment variable on the
base container, sourced from the OS fingerprint profile.

**Required changes:**
- `os_fingerprint.py` — add `tcp_window` field to each OS profile.
- `composer.py` — pass `SPOOF_TCP_WINDOW` env var to base container.
- `templates/base/entrypoint.sh` — new file, applies the iptables rule.
- `templates/base/Dockerfile` — new file, minimal image with `iptables`.

> **Note:** requires `NET_ADMIN` capability (already granted) and the
> `xt_TCPMSS` and `xt_mangle` kernel modules loaded on the host. Both are
> present in any standard Linux distribution kernel.

---

### Phase 3 — ICMP Response Tuning (Medium effort, Medium impact)

nmap's `IE` probe group sends two ICMP echo requests with specific ToS values,
code fields, and payload sizes and inspects what the target returns. Currently
nothing in DECNET controls ICMP echo reply behavior.

**Namespace-scoped sysctls to add per-OS:**

| Sysctl | Effect | Windows | Linux |
|---|---|---|---|
| `net.ipv4.icmp_ratelimit` | Packets/sec rate limit on ICMP errors | `0` (none) | `100` |
| `net.ipv4.icmp_ratemask` | Which ICMP types are rate-limited | `0` | `6168` |

**Expected result:** nmap's `IE` response classification improves from
"no response / filtered" to a correctly typed ICMP echo reply with OS-correct
rate limiting behavior.

---

### Phase 4 — IP ID Sequence Behavior (Hard, Medium impact)

nmap's SEQ probe group fires 6 TCP SYN packets in rapid succession and measures
the **IP ID increment pattern** across responses:

| OS | IP ID pattern | nmap label |
|---|---|---|
| Windows (most) | Sequential, incrementing | `I` (incremental) |
| Linux 3.x+ | Per-socket hashed/random | `RI` or `RD` |
| Old Linux / BSD | Global counter (truly sequential) | `I` |
| Embedded | Often constant 0 or sequential | varies |

Linux switched to per-socket hashed IDs at the kernel level (~3.x). This
**cannot be changed per network namespace** without patching the kernel or
replacing the TCP/IP stack with a userspace implementation.

**Options:**
1. **Accept the limitation** — the IP ID pattern is one of many signals; getting
   TTL + window + timestamps right is already a very strong fingerprint match.
2. **Userspace TCP proxy** (e.g., `lwIP` or a custom `nfqueue`-based responder)
   that intercepts SYN packets and replies with forged ID sequences. High
   complexity; requires `NFQUEUE` kernel module and `libnetfilter_queue`.

> Phase 4 is **not recommended** for the near term. The complexity-to-realism
> ratio is poor compared to Phases 1–3.

---

## Implementation Priority

```
Phase 1  ──────────────────────────────────  (implement next)
  └─ 5 new sysctls in os_fingerprint.py
  └─ No new files, no Docker changes
  └─ Estimated effort: 30 min

Phase 2  ──────────────────────────────────  (implement after Phase 1)
  └─ templates/base/Dockerfile + entrypoint.sh
  └─ os_fingerprint.py: add tcp_window field
  └─ composer.py: pass env var to base container
  └─ Estimated effort: 2–3 hours + tests

Phase 3  ──────────────────────────────────  (nice to have)
  └─ 2 more sysctls in os_fingerprint.py
  └─ Estimated effort: 15 min (after Phase 1 infra exists)

Phase 4  ──────────────────────────────────  (not recommended short-term)
  └─ Requires kernel-level or userspace TCP stack work
  └─ Estimated effort: days
```

---

## Testing Strategy

After each phase, validate with:

```bash
# Active OS fingerprint scan against a deployed decky
sudo nmap -O --osscan-guess <decky_ip>

# Passive fingerprinting (run on host while generating traffic to decky)
sudo p0f -i <macvlan_interface> -p

# Quick TTL + window check
sudo nmap -sS --script banner <decky_ip>
hping3 -S -p 22 <decky_ip>   # inspect TTL and window in reply
```

Expected outcomes by phase:

| Check | Pre-Phase 1 | Post-Phase 1 | Post-Phase 2 |
|---|---|---|---|
| TTL | ✅ | ✅ | ✅ |
| TCP timestamps | ❌ | ✅ | ✅ |
| TCP window size | ❌ | ❌ | ✅ |
| ICMP behavior | ❌ | ⚠️ | ⚠️ |
| IP ID sequence | ❌ | ❌ | ❌ |
| `nmap -O` family match | ⚠️ | ✅ | ✅ |
| `p0f` match | ⚠️ | ⚠️ | ✅ |
