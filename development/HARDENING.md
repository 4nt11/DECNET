# OS Fingerprint Spoofing — Hardening Roadmap

This document describes the current state of OS fingerprint spoofing in DECNET
and the planned improvements to make `nmap -O`, `p0f`, and similar passive/active
scanners see the intended OS rather than a generic Linux kernel.

---

## Current State (Post-Phase 1)

Phase 1 is **implemented and tested against live scans**. Each archetype declares
an `nmap_os` slug (e.g. `"windows"`, `"linux"`, `"embedded"`). The **composer**
resolves that slug via `os_fingerprint.get_os_sysctls()` and injects the resulting
kernel parameters into the **base container** as Docker `sysctls`. Service
containers inherit the same network namespace via `network_mode: "service:<base>"`
and therefore appear identical to outside scanners.

### Implemented sysctls (8 per OS profile)

| Sysctl | Purpose | Win | Linux | Embedded |
|---|---|---|---|---|
| `net.ipv4.ip_default_ttl` | TTL discriminator | `128` | `64` | `255` |
| `net.ipv4.tcp_syn_retries` | SYN retransmit count | `2` | `6` | `3` |
| `net.ipv4.tcp_timestamps` | TCP timestamp option (OPS probes) | `0` | `1` | `0` |
| `net.ipv4.tcp_window_scaling` | Window scale option | `1` | `1` | `0` |
| `net.ipv4.tcp_sack` | Selective ACK option | `1` | `1` | `0` |
| `net.ipv4.tcp_ecn` | ECN negotiation | `0` | `2` | `0` |
| `net.ipv4.ip_no_pmtu_disc` | DF bit in ICMP replies | `0` | `0` | `1` |
| `net.ipv4.tcp_fin_timeout` | FIN_WAIT_2 timeout (seconds) | `30` | `60` | `15` |

### Live scan results (Windows decky, 2026-04-10)

**What works:**

| nmap field | Expected | Got | Status |
|---|---|---|---|
| TTL (`T=`) | `80` (128 dec) | `T=80` | ✅ |
| TCP timestamps (`TS=`) | `U` (unsupported) | `TS=U` | ✅ |
| ECN (`CC=`) | `N` | `CC=N` | ✅ |
| TCP window (`W1=`) | `FAF0` (64240) | `W1=FAF0` | ✅ |
| Window options (`O1=`) | `M5B4NNSNWA` | `O1=M5B4NNSNWA` | ✅ |
| SACK | present | present | ✅ |
| DF bit | `DF=Y` | `DF=Y` | ✅ |

**What fails:**

| nmap field | Expected (Win) | Got | Impact |
|---|---|---|---|
| IP ID (`TI=`) | `I` (incremental) | `Z` (all zeros) | **Critical** — no Windows fingerprint in nmap's DB has `TI=Z`. This alone causes 91% confidence "Linux 2.4/2.6 embedded" |
| ICMP rate limiting | unlimited | Linux default rate | Minor — affects `IE`/`U1` probe groups |

**Key finding:** `TI=Z` is the **single remaining blocker** for a convincing
Windows fingerprint. Everything else (TTL, window, timestamps, ECN, SACK, DF)
is already correct. The Phase 2 window mangling originally planned is
**unnecessary** — the kernel already produces the correct 64240 value.

---

## Remaining Improvement Phases

### Phase 2 — ICMP Tuning via Sysctls (Low effort, Medium impact)

Two additional namespace-scoped sysctls control ICMP error rate limiting.
nmap's `IE` and `U1` probe groups measure how quickly the target responds to
ICMP and UDP-to-closed-port probes.

**Changes required:** add to `OS_SYSCTLS` in `decnet/os_fingerprint.py`.

| Sysctl | What it controls | Windows | Linux | Embedded |
|---|---|---|---|---|
| `net.ipv4.icmp_ratelimit` | Minimum ms between ICMP error messages | `0` (none) | `1000` (1/sec) | `1000` |
| `net.ipv4.icmp_ratemask` | Bitmask of ICMP types subject to rate limiting | `0` | `6168` | `6168` |

**Why:** Windows does not rate-limit ICMP error responses. Linux defaults to
1000ms between ICMP errors (effectively 1 per second per destination). When
nmap sends rapid-fire UDP probes to closed ports, a Windows machine replies to
all of them instantly while a Linux machine throttles responses. Setting
`icmp_ratelimit=0` for Windows makes the `U1` probe response timing match.

**Estimated effort:** 15 min — same pattern as Phase 1, just two more entries.

---

### Phase 3 — NFQUEUE IP ID Rewriting (Medium effort, Very high impact)

This is the **highest-priority remaining item** and the only way to fix `TI=Z`.

#### Root cause of `TI=Z`

The Linux kernel's `ip_select_ident()` function sets the IP Identification
field to `0` for all TCP packets where DF=1 (don't-fragment bit set). This is
correct behavior per RFC 6864 ("IP ID is meaningless when DF=1") but no Windows
fingerprint in nmap's database has `TI=Z`. **No namespace-scoped sysctl can
change this** — it's hardcoded in the kernel's TCP stack.

Note: `ip_no_pmtu_disc` does NOT fix this. That sysctl controls Path MTU
Discovery for UDP/ICMP paths only, not TCP IP ID generation. Setting it to 1
for Windows was tested and confirmed to have no effect on `TI=Z`.

#### Solution: NFQUEUE userspace packet rewriting

Use `iptables -t mangle` to send outgoing TCP packets to an NFQUEUE, where a
small Python daemon rewrites the IP ID field before release.

```
                    ┌──────────────────────────┐
 TCP SYN-ACK  ───► │ iptables mangle/OUTPUT   │
                    │ -j NFQUEUE --queue-num 0 │
                    └───────────┬──────────────┘
                                ▼
                    ┌──────────────────────────┐
                    │  Python NFQUEUE daemon   │
                    │  1. Read IP ID field     │
                    │  2. Replace with target  │
                    │     pattern (sequential  │
                    │     for Windows, zero    │
                    │     for embedded, etc.)  │
                    │  3. Recalculate checksum │
                    │  4. Accept packet        │
                    └───────────┬──────────────┘
                                ▼
                         Packet goes out
```

**Target IP ID patterns by OS:**

| OS | nmap label | Pattern | Implementation |
|---|---|---|---|
| Windows | `TI=I` | Sequential, incrementing by 1 per packet | Global atomic counter |
| Linux 3.x+ | `TI=Z` | Zero (DF=1) or randomized | Leave untouched (already correct) |
| Embedded/Cisco | `TI=I` or `TI=Z` | Varies by device | Sequential or zero |
| BSD | `TI=RI` | Randomized incremental | Counter + small random delta |

**Two possible approaches:**

1. **TCPOPTSTRIP + NFQUEUE (comprehensive)**
   - `TCPOPTSTRIP` can strip/modify TCP options (window scale, SACK, etc.)
     via pure iptables rules, no userspace needed
   - `NFQUEUE` handles IP-layer rewriting (IP ID) in userspace
   - Combined: full control over the TCP/IP fingerprint

2. **NFQUEUE only (simpler)**
   - Single Python daemon handles everything: IP ID rewriting, and optionally
     TCP option/window manipulation if ever needed
   - Fewer moving parts, one daemon to monitor

**Required changes:**
- `templates/base/Dockerfile` — new, installs `iptables` + `python3-netfilterqueue`
- `templates/base/entrypoint.sh` — new, sets up iptables rules + launches daemon
- `templates/base/nfq_spoofer.py` — new, the NFQUEUE packet rewriting daemon
- `os_fingerprint.py` — add `ip_id_pattern` field to each OS profile
- `composer.py` — pass `SPOOF_IP_ID` env var + use `templates/base/Dockerfile`
  instead of bare distro images for base containers

**Dependencies on the host kernel:**
- `nfnetlink_queue` module (`modprobe nfnetlink_queue`)
- `xt_NFQUEUE` module (standard in all distro kernels)
- `NET_ADMIN` capability (already granted)

**Dependencies in the base container image:**
- `iptables` package
- `python3` + `python3-netfilterqueue` (or `scapy` with `NetfilterQueue`)

**Estimated effort:** 4–6 hours + tests

---

### Phase 4 — Full Fingerprint Database Matching (Hard, Low marginal impact)

After Phases 2–3, the remaining fingerprint differences are increasingly minor:

| Signal | Current | Notes |
|---|---|---|
| TCP initial sequence number (ISN) pattern (`SP=`, `ISR=`) | Linux kernel default | Kernel-level, not spoofable without userspace TCP |
| TCP window variance across probes | Constant (`FAF0` × 6) | Real Windows sometimes varies slightly |
| T2/T3 responses | `R=N` (no response) | Correct for some Windows, wrong for others |
| ICMP data payload echo | Linux default | Difficult to control per-namespace |

These are diminishing returns. With Phases 1–3 complete, `nmap -O` should
correctly identify the OS family in >90% of scans.

> Phase 4 is **not recommended** for the near term. Effort is measured in days
> for single-digit percentage improvements.

---

## Implementation Priority (revised)

```
Phase 1  ✅ DONE ─────────────────────────────
  └─ 8 sysctls per OS in os_fingerprint.py
  └─ Verified: TTL, window, timestamps, ECN, SACK all correct

Phase 2  ──────────────────────────────── (implement next)
  └─ 2 more sysctls: icmp_ratelimit + icmp_ratemask
  └─ Estimated effort: 15 min

Phase 3  ──────────────────────────────── (high priority)
  └─ NFQUEUE daemon in templates/base/
  └─ Fix TI=Z for Windows (THE remaining blocker)
  └─ Estimated effort: 4–6 hours + tests

Phase 4  ──────────────────────────────── (not recommended)
  └─ ISN pattern, T2/T3, ICMP payload echo
  └─ Estimated effort: days, diminishing returns
```

---

## Testing Strategy

After each phase, validate with:

```bash
# Active OS fingerprint scan against a deployed decky
sudo nmap -O --osscan-guess <decky_ip>

# Aggressive scan with version detection
sudo nmap -sV -O -A --osscan-guess <decky_ip>

# Passive fingerprinting (run on host while generating traffic to decky)
sudo p0f -i <macvlan_interface> -p

# Quick TTL + window check
hping3 -S -p 445 <decky_ip>   # inspect TTL and window in reply

# Test INI (all OS families, 10 deckies)
sudo .venv/bin/decnet deploy --config arche-test.ini --interface eth0
```

### Expected outcomes by phase

| Check | Pre-Phase 1 | Post-Phase 1 ✅ | Post-Phase 2 | Post-Phase 3 |
|---|---|---|---|---|
| TTL | ✅ | ✅ | ✅ | ✅ |
| TCP timestamps | ❌ | ✅ | ✅ | ✅ |
| TCP window size | ❌ | ✅ (kernel default OK) | ✅ | ✅ |
| ECN | ❌ | ✅ | ✅ | ✅ |
| ICMP rate limiting | ❌ | ❌ | ✅ | ✅ |
| IP ID sequence (`TI=`) | ❌ | ❌ | ❌ | ✅ |
| `nmap -O` family match | ⚠️ | ⚠️ (TI=Z blocks) | ⚠️ | ✅ |
| `p0f` match | ⚠️ | ⚠️ | ✅ | ✅ |

### Note on `P=` field in nmap output

The `P=x86_64-redhat-linux-gnu` that appears in the `SCAN(...)` block is the
**GNU build triple of the nmap binary itself**, not a fingerprint of the target.
It cannot be changed and is not relevant to OS spoofing.
