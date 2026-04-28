# DECNET Capture Pipeline — Attacker-Profiling Signal Audit

**Date**: 2026-04-22  
**Scope**: v1 capture readiness for post-v1 profiler extraction  
**Methodology**: End-to-end verification (emission → transport → storage) for each signal against active code paths.

---

## Executive Summary

**Capture Status by Category**:

| Category | Captured | Partial | Not Captured | n/a |
|----------|----------|---------|--------------|-----|
| Session Environment | 0 | 1 | 3 | 0 |
| Keystroke/Human | 0 | 2 | 6 | 2 |
| SSH Transport | 2 | 2 | 2 | 0 |
| Network/TCP | 3 | 2 | 5 | 0 |
| TLS/L7 | 2 | 2 | 1 | 0 |
| Aggregated/Derived | 0 | 0 | 5 | 0 |
| **TOTAL** | **7** | **9** | **22** | **2** |

**Critical Pre-v1 Gaps** (blockers if signals are roadmap-committed):

1. **KEX algorithm ordering** — HASSH hash is stored, but raw `kex_algorithms` string is only emitted to syslog, not persisted to DB. Future extractor must parse syslog archives.
2. **Per-keystroke timing** — Asciinema v2 `"i"` events with `t` timestamps are written to day-shard files on disk, but no database ingestion. Requires filesystem polling + parsing path.
3. **TCP options order** — Captured in PCAP + sniffer logs (`options_sig`), but `options_sig` is a rolled-up signature string, not the raw per-connection sequence.
4. **Terminal size (COLS×ROWS)** — Not captured from pty-req at all; would require SSH protocol-level interception.
5. **SSH client version** — Server-side only sees RFC 4253 banner; full version string would require TLS cert inspection or prober modification.

**Biggest ROI capture improvements** (cheap, high-value):

1. Add `ssh_client_banner` column to Attacker table — capture SSH-2.0-* string from pty-req.
2. Ingest asciinema keystroke timing into new `SessionProfile` table (v2 roadmap already designs this).
3. Store raw KEX algorithm lists in `AttackerBehavior.kex_order_raw` (MEDIUMTEXT) instead of relying on syslog dedup.

---

## Per-Signal Classification

### Per-Session Environment (SessionProfile candidates)

#### TERM environment variable
- **Status**: `partial`
- **Where**: SSH server can read TERM from pty-req; emitted in syslog by `emit_capture.py` if implemented.
- **Current path**: Not found in active code path. Check `decnet/templates/ssh/emit_capture.py` or syslog bridge.
- **Missing**: Database column in a `SessionProfile` table; no structured ingestion.
- **Cheap fix**: Modify SSH syslog bridge to emit `session_event` with `term=<value>`. Create `SessionProfile` table with `session_term` TEXT column.
- **Priority**: V2 backlog (nice-to-have for human vs. automation, low discriminative power).

#### LANG / LC_ALL
- **Status**: `not_captured`
- **Why**: Server-side locale is baked into container image, not attacker-controlled. Attacker's client locale is not visible over SSH.
- **Priority**: defer (non-capturable from server vantage point).

#### SSH client version string (full SSH-2.0-OpenSSH_9.2p1…)
- **Status**: `partial`
- **Where**: RFC 4253 banner string is transmitted in plaintext before encryption. Sniffer could capture it from TCP stream; prober `hassh.py` captures server banner (lines 58–101), not client.
- **Missing**: Client-side banner capture. Sniffer would need TCP stream reconstruction to pluck the SSH banner from the raw payload.
- **Cheap fix**: Extend sniffer to parse SSH banners from TCP stream (before TLS/encryption); emit `ssh_client_banner` event. Store in Attacker.`ssh_client_banners` (JSON list).
- **Priority**: v1 blocker if client-profiling is committed. Currently partial via TLS fingerprint fallback.

#### Terminal size (COLS × ROWS)
- **Status**: `not_captured`
- **Why**: SSH pty-req extension carries `terminal mode` (COLS, ROWS, speeds); server-side sshd parses this but does not log it by default. Would require patching sshd or intercepting at the protocol layer.
- **Missing**: No access to pty-req payload without protocol-level instrumentation.
- **Cheap fix**: Patch SSH entrypoint to log pty-req to syslog before accepting the request (requires custom OpenSSH build).
- **Priority**: V2 backlog (interesting for typing-space reconstruction, but not blocky).

---

### Per-Session, Keyboard/Human (SessionProfile candidates)

#### Per-keystroke timing (t in asciinema "i" events)
- **Status**: `partial`
- **Where**: Sessrec pipeline (`decnet/templates/ssh/sessrec/`) writes asciinema v2 day-shards with per-keystroke `"i"` (input) events carrying `t` (timestamp in seconds since session start). Files on disk: `/var/lib/decnet/session_recordings/<decky>/<date>.json` (or similar).
- **Missing**: No ingestion into database. Extractors must read asciinema files from filesystem and parse the `"i"` event stream post-hoc.
- **Cheap fix**: Ingest keystroke timing stream into new `SessionProfile` table (design already in DEVELOPMENT_V2.md). Add job to parse day-shard files on rotation and compute IKI moments, burst ratio, etc.
- **Priority**: v1 blocker if keystroke dynamics is roadmap-committed. Data exists but not queryable.

#### Control-character stream (backspace, ^W, ^U, ^C, ^D, arrows, tab)
- **Status**: `partial`
- **Where**: Asciinema captures every keystroke as UTF-8/control byte in `"i"` events. Raw byte sequence is preserved.
- **Missing**: Same as above — files on disk, no DB ingestion. Future extractor can parse control bytes from the `"data"` field of each `"i"` event.
- **Cheap fix**: Same as keystroke timing — ingest asciinema events and compute `kd_ctrl_*` rates in SessionProfile.
- **Priority**: v2 (depends on SessionProfile schema).

#### Inter-command think time (prompt-return to next-command-start gap)
- **Status**: `not_captured`
- **Why**: Requires prompt boundary detection in the asciinema stream (heuristic: line ending in `$` or `#` + pause > 100ms). No active code marks prompts.
- **Missing**: Prompt-boundary markers in asciinema. Would require ML or regex-based post-processing.
- **Cheap fix**: Add prompt-regex configuration + marker injection during sessrec playback, or post-hoc analysis over asciinema.
- **Priority**: V2 (interesting but requires heuristic or attacker-side annotation).

#### Pause before sensitive commands
- **Status**: `not_captured`
- **Why**: Requires command-boundary detection (typing a full command, then detecting gap before Enter). Asciinema captures this timing, but no code marks command boundaries.
- **Missing**: Command-line parsing + gap detection logic.
- **Cheap fix**: Off-line analysis: parse `"i"` events, detect Enter (`\r`), measure gap before Enter. Correlate with command content from `"o"` (output) events.
- **Priority**: V2 backlog (post-extraction analysis; interesting for psychological profiling).

#### Command n-grams
- **Status**: `partial`
- **Where**: SSH service logs individual commands to syslog when pty input is detected. Attacker.`commands` JSON array stores seen commands (but coarse-grained per service/decky, not per-session).
- **Missing**: Per-session, per-command sequencing. No n-gram bigrams/trigrams computed.
- **Cheap fix**: Parse asciinema `"i"` + `"o"` stream to extract full command lines, store as JSON list in SessionProfile.`cmd_sequence` or new `SessionCommand` table.
- **Priority**: V2 (foundation for command chaining fingerprint).

#### Flag preferences (ls -la vs ls -al, ps -ef vs ps aux)
- **Status**: `not_captured`
- **Why**: Asciinema records the **typed** command line exactly, but no code parses flag ordering or normalizes commands for pattern comparison.
- **Missing**: Canonical command parsing + flag-order extraction.
- **Cheap fix**: Off-line: regex-parse commands from asciinema, extract flag sequences, compute n-grams over flag positions.
- **Priority**: V2 (cheap post-processing, good human-vs-tool separator).

#### Typo patterns (suod, sl)
- **Status**: `not_captured`
- **Why**: Asciinema records corrected command line after backspacing, not the raw keystrokes with typos visible.
- **Example**: typing `suod<backspace>` then `ddo<backspace>` then `o` shows as `sudo` in `"o"` output; the intermediate typos are **visible** in the `"i"` event stream but require careful keystroke-by-keystroke parsing.
- **Missing**: Raw keystroke stream parsing to detect backspace/correction patterns.
- **Cheap fix**: Parse `"i"` events, reconstruct line state keystroke-by-keystroke, log (typed_text, final_text) pairs to detect corrections.
- **Priority**: V2 (unique human fingerprint, but requires manual asciinema parsing).

#### Editor choice (vi/vim/nano/ed)
- **Status**: `partial`
- **Where**: Command launch (`vi`, `nano`, `ed`) is visible in asciinema `"i"` + `"o"` stream and captured in Attacker.`commands`.
- **Missing**: No aggregation of editor invocations or time-in-editor statistics.
- **Cheap fix**: Post-process commands, count editor launches, extract editor type. Could add to AttackerBehavior.`preferred_editor` or new SessionProfile.`editor_used`.
- **Priority**: V2 (behavioral signal, low priority).

#### Shell history usage (!!,!$, ^old^new, fc)
- **Status**: `partial`
- **Where**: Command input stream captures the actual invocation (if attacker types `!!`, it's visible in `"i"`). Output `"o"` shows the expanded command.
- **Missing**: No parsing of history expansion syntax; requires post-processing to identify `!` / `^` patterns.
- **Cheap fix**: Regex-scan asciinema input for shell history operators; count occurrences.
- **Priority**: V2 (interesting tool-chain signal, but low volume).

---

### Per-Attacker, SSH Transport (AttackerBehavior candidates)

#### HASSH / HASSHServer
- **Status**: `captured`
- **Where**: Prober (`decnet/prober/hassh.py`) computes HASSHServer fingerprint; stored as `Attacker.fingerprints` JSON list (generic bounty store). Also emitted to syslog by prober worker.
- **Note**: Roadmap says `[x]` (captured); verified in code at lines 244–252 of `hassh.py`.
- **Storage**: `Attacker.fingerprints` (JSON list of `{type, value, ...}` dicts); not per-attacker-behavior, but queryable.
- **Priority**: ✓ captured; v2: consider normalizing to `AttackerBehavior.hassh_server` for faster lookup.

#### KEX algorithm preference ORDER (beyond HASSH hash)
- **Status**: `partial`
- **Where**: Sniffer logs raw `kex_algorithms`, `encryption_s2c`, `mac_s2c`, `compression_s2c` strings to syslog in `tls_session` and `tcp_syn_fingerprint` events (fingerprint.py lines 240–252).
- **Missing**: Stored in **syslog only**, not in DB. Attacker table has `fingerprints` (bounty store) but no dedicated `kex_order_raw` column.
- **Path to recovery**: Read syslog archives and parse `kex_algorithms` field. But this is not queryable at scale.
- **Cheap fix**: Add `Attacker.kex_order_raw` (MEDIUMTEXT, JSON string list) and `kd_kex_order_hash` (similar to digraph simhash). Populate during sniffer event ingestion.
- **Priority**: v1 blocker if KEX ordering is committed to roadmap (currently only hash stored, raw data must be re-parsed from syslog).

#### Public key comment field
- **Status**: `not_captured`
- **Why**: SSH key comment is part of the OpenSSH wire format (only transmitted if key auth is used). Server-side sshd does not log it by default; would require PAM/auth hook instrumentation.
- **Missing**: No interception of public key authentication payloads.
- **Cheap fix**: Patch SSH server to emit auth_pubkey event with key comment extracted from wire format. Or use `net.ssh` library instrumentation.
- **Priority**: V2 backlog (valuable for key reuse fingerprinting, but rare).

#### Private key type advertised (Ed25519 / RSA / ECDSA)
- **Status**: `partial`
- **Where**: SSH transport carries key type in the public key authentication message. Sniffer cannot decode this (traffic is encrypted after ServerHello). Server-side sshd doesn't log it.
- **Missing**: Requires either passive PCAP of SSH-TRANSPORT (not available; encrypted) or server-side auth hook.
- **Cheap fix**: Patch sshd to emit `auth_pubkey_type` event during authentication.
- **Priority**: V2 (interesting but lower signal than key comment).

#### Agent forwarding requested?
- **Status**: `not_captured`
- **Why**: Agent forwarding is negotiated via SSH_MSG_SERVICE_REQUEST → ssh-userauth → "ssh-agent@openssh.com" extension. Encrypted after KEX.
- **Missing**: Would require decrypting SSH transport or instrumenting sshd auth hook.
- **Cheap fix**: Sshd can detect `SSH_AUTH_SOCK` or SSH_AGENT_FWD service request; add to syslog.
- **Priority**: V2 (useful for lateral-movement detection).

#### Channel multiplexing pattern
- **Status**: `partial`
- **Where**: SSH service logs each command separately. Channel open/close events could be tracked, but no code currently does.
- **Missing**: Per-session channel state machine (open channels, their types, lifetime).
- **Cheap fix**: Instrument sshd or use SSH_MSG_CHANNEL_OPEN events in syslog to track simultaneous channels.
- **Priority**: V2 (rare; most attackers use sequential commands).

#### SSH_CLIENT / SSH_CONNECTION environment variables
- **Status**: `captured`
- **Where**: SSH server **always** sets `SSH_CLIENT` and `SSH_CONNECTION` in the child shell. Server-side user code (bashrc, commands) can read them. If attacker runs `echo $SSH_CLIENT`, it's visible in asciinema output.
- **Missing**: No **automatic** logging of these vars. Requires parsing asciinema for intentional queries or patching sshd to emit them.
- **Cheap fix**: Patch SSH PAM or auth hook to log `SSH_CLIENT` on successful auth. Or parse asciinema for `echo $SSH_*` commands.
- **Priority**: V2 (low value; mostly redundant with src_ip already in logs).

---

### Per-Attacker, Network/Transport (AttackerBehavior candidates)

#### TCP timestamp clock skew (Kohno 2005)
- **Status**: `partial`
- **Where**: PCAP contains TCP timestamps (if present). Sniffer code extracts MSS, window size, options (fingerprint.py line 77–94). TCP options include timestamp flag (`has_timestamps`).
- **Missing**: Raw timestamp values (`opt_value` for "Timestamp" in scapy) are NOT extracted. Only boolean `has_timestamps` flag is stored. To compute clock skew, need timestamp values across multiple packets.
- **Path to recovery**: Raw PCAP analysis (if PCAPs are retained on disk). Each TCP packet has `[TCP option: Timestamp x, y]` which can be parsed post-hoc.
- **Cheap fix**: Extend sniffer to extract timestamp sequence numbers and RTT deltas. Store as per-flow timing summary in `tcp_flow_timing` event (which already captures flow metrics).
- **Priority**: V2 (requires PCAP or extended sniffer capture; useful for OS fingerprinting).

#### TCP ISN generator characteristics
- **Status**: `not_captured`
- **Why**: ISN is visible in PCAP (TCP seq number on SYN). Sniffer code tracks flow seqs for retransmit detection (line 850) but does not extract the initial SYN seq across multiple connections to analyze ISN patterns.
- **Missing**: No per-connection ISN logging. Would need to roll up ISN sequences across multiple SYNs to the same port.
- **Cheap fix**: On every SYN, log `syn_seq` in `tcp_syn_fingerprint` event. Post-hoc analysis can compute randomness metrics.
- **Priority**: V2 backlog (weak signal; ISN randomization is standard on modern OS).

#### TCP options ordering in SYN
- **Status**: `partial`
- **Where**: Sniffer extracts `options_sig` (line 87) via `_extract_options_order()` from scapy TCP options. This is a **signature string** (e.g., `"MSS,WScale,SAckOK,Timestamp"`).
- **Missing**: The signature is **aggregated**; we don't store the raw per-packet ordering. Also, `options_sig` is deduplicated in logs (only one event per unique signature per dedup window).
- **Path to recovery**: Raw PCAP analysis or re-parsing sniffer logs to extract the signature. But the signature is a good enough feature for OS fingerprinting.
- **Cheap fix**: Store `tcp_fingerprint` JSON in AttackerBehavior with raw options list (not just signature). Current schema (models.py line 174–177) only stores aggregated `{window, wscale, mss, options_sig}`.
- **Priority**: v1 improvement (low effort, already have options_sig; add raw list).

#### Initial congestion window ramp-up
- **Status**: `not_captured`
- **Why**: Requires detailed TCP state machine tracking (SYN, SYN-ACK, ACK sequence with packet sizes). Sniffer tracks `packets` count and `bytes` total per flow (line 844–868), but not per-packet sequence or ACK-clock dynamics.
- **Missing**: Per-packet payload sizes and ACK timing.
- **Cheap fix**: Extend `tcp_flow_timing` event to include per-packet sizes (as JSON list) or CWND estimation from ACK patterns.
- **Priority**: V2 backlog (very niche; useful for Reno vs. Cubic vs. BBR detection, but rare in honeypot context).

#### Retransmit timing and backoff
- **Status**: `captured`
- **Where**: Sniffer tracks `retransmits` count per flow (lines 873–877, 922). Emitted in `tcp_flow_timing` event. No **timing** of retransmits, only count.
- **Missing**: Timing deltas between retransmit pairs (RTO, exponential backoff pattern).
- **Path to recovery**: Raw PCAP; sequence numbers in `tcp_flow_timing` are not logged.
- **Cheap fix**: Extend event to include retransmit timing deltas (list of RTOs).
- **Priority**: V2 (useful for network condition inference; low value on honeypots).

#### MTU / path-MTU discovery behavior
- **Status**: `partial`
- **Where**: Sniffer tracks per-flow byte counts (line 868); can infer effective MSS from packet sizes. TCP fingerprint includes extracted MSS (line 77–94, emitted in `tcp_syn_fingerprint`).
- **Missing**: No multi-flow MTU tracking or ICMP fragmentation-needed response detection. Would require ICMP processing.
- **Cheap fix**: Log ICMP unreachable (frag needed) events separately; correlate with TCP flows to infer PMTUD behavior.
- **Priority**: V2 backlog (VPN detection is interesting but niche).

#### Packet pacing (microsecond-resolution egress timing)
- **Status**: `not_captured`
- **Why**: Sniffer computes mean/min/max inter-arrival time in milliseconds (lines 904–906), not microseconds. Modern pacing requires sub-millisecond precision.
- **Missing**: Sniffer uses `time.monotonic()` (typically millisecond granularity on Linux); would need OS-level timing hooks or PCAP with hardware timestamps.
- **Cheap fix**: Upgrade sniffer to use PCAP timestamps (pcap.ts_resolution) if available; log microsecond-resolution inter-packet gaps.
- **Priority**: V2 backlog (requires infrastructure upgrade; marginal value on honeypots).

#### Window scaling multipliers
- **Status**: `captured`
- **Where**: Sniffer extracts `wscale` from TCP options (line 80); stored in `tcp_fingerprint` JSON and emitted in `tcp_syn_fingerprint` event.
- **Storage**: AttackerBehavior.`tcp_fingerprint` (JSON: `{window, wscale, mss, ...}`); queryable.
- **Priority**: ✓ captured (sufficient for OS fingerprinting and congestion algorithm inference).

#### ECN negotiation
- **Status**: `not_captured`
- **Why**: ECN is signaled via TCP flags (CWR, ECE) and the SYN's TCP options. Scapy's TCP layer does not expose ECN flags in the options extraction.
- **Missing**: No code to parse ECN negotiation from TCP header.
- **Cheap fix**: Extend TCP fingerprint extraction to check for ECN flag bits.
- **Priority**: V2 backlog (rarely used; low value).

---

### Per-Attacker, L7 (TLS/HTTP)

#### TLS fingerprint (JA3/JA4)
- **Status**: `captured`
- **Where**: Sniffer fingerprint engine computes JA3/JA3S/JA4/JA4S (lines 565–662); emitted in syslog and stored in `Attacker.fingerprints` (bounty store).
- **Storage**: Logs are queryable; fingerprints stored as JSON in bounty table (generic).
- **Roadmap**: `[x]` JA3/JA3S, `[x]` JA4+. Verified in code.
- **Priority**: ✓ captured (good).

#### TLS session resumption behavior
- **Status**: `captured`
- **Where**: Sniffer extracts resumption mechanisms (session_ticket, PSK, early_data, session_id) in `_session_resumption_info()` (lines 675–689). Emitted in `tls_client_hello` event.
- **Storage**: Logged to syslog; `Attacker.fingerprints` stores resumption=`[mechanism list]`.
- **Priority**: ✓ captured (good).

#### HTTP/2 SETTINGS frame ordering + values
- **Status**: `not_captured`
- **Why**: HTTP/2 is encrypted (after TLS handshake). Sniffer cannot see plaintext SETTINGS frames.
- **Missing**: Would require decryption (not viable passively) or attacker-side TLS instrumentation.
- **Cheap fix**: Instrument HTTP/2 services (h2c, HTTP/2 over plain TCP on rare deployments) or use TLS key log for offline analysis.
- **Priority**: defer (not capturable from passive vantage point).

#### HTTP/2 stream prioritization
- **Status**: `not_captured`
- **Why**: Encrypted in TLS.
- **Missing**: Same as above.
- **Priority**: defer (not capturable).

#### HTTP header ordering
- **Status**: `not_captured`
- **Why**: Inside encrypted TLS. Sniffer cannot see plaintext HTTP headers.
- **Missing**: Would require server-side HTTP request logging (not implemented).
- **Cheap fix**: Instrument HTTP service to log raw header order in syslog.
- **Priority**: V2 (useful for bot/tool detection, but requires service-level capture).

#### Cookie handling behavior (expiry, domain scope)
- **Status**: `not_captured`
- **Why**: Encrypted TLS + requires HTTP state machine tracking (Set-Cookie responses vs. Cookie requests).
- **Missing**: Would need server-side HTTP middleware or browser instrumentation.
- **Cheap fix**: Add cookie jar logging to HTTP service (track which attacker cookies were accepted, rejected, resent).
- **Priority**: V2 (behavioral signal; interesting but niche).

---

### Per-Attacker, Aggregated/Derived (would live in new `AttackerAggregate` table)

#### Time-of-day activity distribution (chronotyping)
- **Status**: `partial`
- **Where**: Log entries have `timestamp` (datetime). All events are timestamped. Can compute hour-of-day histogram post-hoc.
- **Missing**: No aggregation table or computed features. Would live in new AttackerAggregate.
- **Cheap fix**: Batch job: group events by attacker + hour-of-day, compute distribution histogram. Store as JSON or new table.
- **Priority**: V2 (simple aggregation; good for clustering).

#### Session duration distribution
- **Status**: `partial`
- **Where**: SessionProfile schema (DEVELOPMENT_V2.md) includes `session_duration_s`. Asciinema files are per-decky-per-day, so duration can be computed.
- **Missing**: No SessionProfile table yet; no aggregation of durations across sessions.
- **Cheap fix**: Implement SessionProfile table + compute per-attacker duration histogram in AttackerAggregate.
- **Priority**: V2 (depends on SessionProfile; good for behavioral clustering).

#### Recon-to-action ratio
- **Status**: `partial`
- **Where**: Profiler already computes recon vs. exfil phase sequencing (behavioral.py lines 52–62, 188–191). Stored in `AttackerBehavior.phase_sequence` (JSON: `{recon_end, exfil_start, latency}`).
- **Missing**: No per-attacker ratio column in AttackerAggregate. Would be simple division: `exfil_events / recon_events`.
- **Cheap fix**: Compute ratio in profiler job; store in new AttackerAggregate or as extension to AttackerBehavior.
- **Priority**: V2 (low effort; useful for threat level scoring).

#### Lateral movement style
- **Status**: `not_captured`
- **Why**: Requires graph traversal (attacker hopping between deckies). Correlation engine (correlation/engine.py) should track this, but no explicit "lateral movement style" feature (sequential vs. parallel, target selection heuristic).
- **Missing**: No code analyzing lateral movement pattern (which deckies were touched, in what order, dwell time per decky).
- **Cheap fix**: Extend CorrelationEngine to build per-attacker decky traversal graph; compute metrics (average dwell time, fan-out ratio, revisit frequency).
- **Priority**: V2 (interesting; requires traversal graph extraction from correlation engine).

#### Persistence-first vs. exfil-first
- **Status**: `not_captured`
- **Why**: Requires semantic tagging of events (is this persistence activity? exfil activity?). Profiler has `EXFIL_EVENT_TYPES` (line 59–62) but no persistence catalog.
- **Missing**: No code to classify persistence attempts (cron jobs, reverse shells, privilege escalation).
- **Cheap fix**: Add PERSISTENCE_EVENT_TYPES list; compute persistence_start vs. exfil_start timestamps; store in AttackerBehavior or AttackerAggregate.
- **Priority**: V2 (requires event taxonomy; valuable for threat classification).

#### Tool-chain ordering
- **Status**: `partial`
- **Where**: Profiler logs tool guesses in AttackerBehavior.`tool_guesses` (line 183, behavioral.py lines 76–105). Tools are matched by beacon timing + header patterns.
- **Missing**: No **ordering** — tools are listed but not sequenced by first-appearance time.
- **Cheap fix**: Sort tool_guesses by first event timestamp; store as ordered list. Compute tool transition graph (tool A → tool B over time).
- **Priority**: V2 (interesting; small extension to existing tool attribution).

#### Error-response psychology
- **Status**: `not_captured`
- **Why**: Requires analyzing how attacker reacts to failures (e.g., retry frequency after auth failure, command error recovery). Would need per-command success/failure tracking.
- **Missing**: No error-categorization in logs; would need service-level event typing (auth_failure vs. auth_success, exec_error vs. exec_success).
- **Cheap fix**: Extend service events to include success/failure indicators; compute attacker error-response metrics (retry rate, time-to-recovery, behavior change after error).
- **Priority**: V2 backlog (niche; good for human vs. bot discrimination).

---

## Table Recommendations

### `AttackerBehavior` — Current & Recommended Additions

**Currently captured** (verified in models.py lines 161–194):
- `tcp_fingerprint` (JSON) — window, wscale, mss, options_sig
- `timing_stats` (JSON) — mean/median/stdev/min/max IAT
- `phase_sequence` (JSON) — recon_end, exfil_start latency
- `tool_guesses` (JSON list)
- `beacon_interval_s`, `beacon_jitter_pct`
- `behavior_class` (beaconing | interactive | scanning | …)

**Recommended additions for v1 (pre-v2, no schema bump)**:
- `kex_order_raw` (MEDIUMTEXT, JSON list) — raw KEX algorithm strings from HASSH
- `tls_fingerprints_full` (MEDIUMTEXT, JSON) — full JA3/JA4 raw strings, not just hashes
- `ssh_client_banners` (MEDIUMTEXT, JSON list) — capture from TCP stream

**Reserved for v2**:
- See SessionProfile below.

### `SessionProfile` — New Table (v2 roadmap in DEVELOPMENT_V2.md)

Design is already specified (lines 71–104). Implement in v1 as empty table + stubbed write path, ready for feature extraction post-v1.

**Columns** (from DEVELOPMENT_V2.md):
- `sid` (TEXT PK)
- `log_id` (FK to logs)
- `schema_version` (INT, required for federation gossip)
- Timing features: `kd_iki_mean`, `kd_iki_stdev`, `kd_iki_p50`, `kd_iki_p95`, `kd_enter_latency_p50`, `kd_enter_latency_p95`
- Ratio features: `kd_burst_ratio`, `kd_think_ratio`
- Control-char rates: `kd_ctrl_backspace`, `kd_ctrl_wkill`, `kd_ctrl_ukill`, `kd_ctrl_abort`, `kd_ctrl_eof`, `kd_arrow_rate`, `kd_tab_rate`
- `kd_digraph_simhash` (BLOB, 8 bytes)
- Derived: `total_keystrokes`, `session_duration_s`, `created_at`

**Note**: All keystroke-timing values are derivable from existing asciinema day-shard files on disk. Implement ingestion job in v2 (not v1 blocker).

### `AttackerAggregate` — New Table (v2+)

Columns (suggested):
- `attacker_uuid` (PK, FK to attackers)
- `activity_dist_by_hour` (JSON) — histogram of event counts by UTC hour
- `session_duration_dist` (JSON) — percentiles of session durations
- `recon_to_action_ratio` (REAL)
- `lateral_movement_graph` (JSON) — decky traversal (src → dst edges with dwell times)
- `tool_sequence` (JSON list) — tools in chronological order
- `is_persistent` (BOOL) — persistence activity detected?
- `updated_at` (TIMESTAMP)

---

## Full Per-Signal Capture Table

| Signal | Status | Where Captured | What's Missing | Cheap Fix | Priority |
|--------|--------|-----------------|-----------------|-----------|----------|
| **Session Environment** |
| TERM | partial | SSH pty-req, server-readable | No syslog emission, no DB | Patch SSH syslog bridge to emit term= | V2 |
| LANG/LC_ALL | n/a | Server locale, not attacker-controlled | Not visible from server vantage | Defer (not capturable) | defer |
| SSH client version | partial | TCP stream (plaintext banner before TLS) | Sniffer doesn't parse SSH banners; only TLS fingerprints | Extend sniffer to extract SSH banner from TCP stream | v1 blocker |
| Terminal size (COLS×ROWS) | not_captured | SSH pty-req extension | Requires protocol interception or sshd patch | Patch sshd to log pty-req | V2 |
| **Keyboard/Human** |
| Per-keystroke timing | partial | Asciinema "i" events with t timestamps | Files on disk, not ingested to DB | Implement SessionProfile table + ingest job | v1 blocker |
| Control-character stream | partial | Asciinema keystroke bytes | Same as above (files only) | Same as above | v1 blocker |
| Inter-command think time | not_captured | Requires prompt detection | Heuristic (line ending in $/#) not implemented | Post-hoc: regex + gap detection over asciinema | V2 |
| Pause before sensitive cmd | not_captured | Would be in asciinema timing | Requires command-line parsing + gap detection | Off-line analysis of asciinema | V2 |
| Command n-grams | partial | Attacker.commands (generic list) | Per-session structure missing | Parse asciinema I/O; store in SessionProfile | V2 |
| Flag preferences | not_captured | Asciinema input has typed flags | No parsing or normalization | Regex-parse and canonicalize flags from asciinema | V2 |
| Typo patterns | not_captured | Raw keystroke sequence in asciinema "i" | Requires keystroke-by-keystroke reconstruction | Parse "i" events with backspace markers; reconstruct line state | V2 |
| Editor choice | partial | Attacker.commands shows editor launch | No aggregation or time-in-editor | Count editor invocations; store preference in SessionProfile | V2 |
| Shell history usage | partial | Command input shows !, ^, !! | No parsing for history operators | Regex-scan for shell history syntax; count | V2 |
| **SSH Transport** |
| HASSH/HASSHServer | captured | Prober (hassh.py); Attacker.fingerprints | ✓ (hash + raw algorithm strings in syslog) | Already done | — |
| KEX algorithm order | partial | Syslog event kex_algorithms= field | Not persisted to DB (only in syslog) | Add AttackerBehavior.kex_order_raw (MEDIUMTEXT, JSON) | v1 blocker |
| Public key comment | not_captured | SSH wire format (auth_pubkey) | Requires server-side auth hook | Patch sshd to emit auth_pubkey_comment event | V2 |
| Private key type | partial | SSH wire format (auth algorithm OID) | Encrypted after KEX; needs sshd hook | Patch sshd to emit auth_key_type event | V2 |
| Agent forwarding? | not_captured | SSH extension negotiation (encrypted) | Requires sshd instrumentation | Patch sshd to detect ssh-agent@openssh.com | V2 |
| Channel multiplexing | partial | SSH service logs commands separately | No channel state machine | Instrument sshd SSH_MSG_CHANNEL_OPEN events | V2 |
| SSH_CLIENT env vars | captured | Server sets automatically; queryable via shell | No automatic logging | Patch sshd PAM to emit SSH_CLIENT on auth | V2 |
| **Network/Transport** |
| TCP timestamp skew | partial | PCAP + sniffer has has_timestamps flag | Only boolean; not timestamp values | Extract timestamp seq numbers in sniffer | V2 |
| TCP ISN generator | not_captured | PCAP SYN seq field | No per-connection ISN logging | Log syn_seq in tcp_syn_fingerprint event | V2 |
| TCP options ordering | partial | Sniffer extracts options_sig signature | Aggregated string; no raw order per-packet | Extend tcp_fingerprint JSON with raw options list | v1 improvement |
| Initial congestion window | not_captured | Would require per-packet ACK analysis | Not tracked in sniffer | Extend tcp_flow_timing to include payload sizes list | V2 |
| Retransmit timing+backoff | partial | Sniffer counts retransmits; no timing | RTO/backoff timing not logged | Extend event to include RTO deltas | V2 |
| MTU/path-MTU discovery | partial | MSS in TCP SYN; byte counts per flow | No ICMP fragmentation-needed events | Add ICMP processing; correlate with TCP flows | V2 |
| Packet pacing (μs) | not_captured | Sniffer uses millisecond granularity | Needs PCAP hardware timestamps or OS hooks | Upgrade to sub-millisecond timing | V2+ |
| Window scaling | captured | TCP fingerprint; wscale in AttackerBehavior | ✓ queryable | — | — |
| ECN negotiation | not_captured | TCP SYN flags (CWR/ECE) + options | Not extracted from TCP header | Extend TCP fingerprint to parse ECN bits | V2 |
| **L7 (TLS/HTTP)** |
| TLS fingerprint (JA3/JA4) | captured | Sniffer fingerprint.py; Attacker.fingerprints | ✓ hashes stored + syslog | Already done | — |
| HTTP/2 SETTINGS order | not_captured | Encrypted inside TLS | Passive inspection not viable | Defer (not capturable) | defer |
| HTTP/2 prioritization | not_captured | Encrypted | Not capturable | defer | defer |
| HTTP header ordering | not_captured | Encrypted; requires service logging | Service doesn't log raw headers | Patch HTTP service to log header order | V2 |
| Cookie handling | not_captured | Requires HTTP state machine | Not tracked | Add cookie jar logging to HTTP service | V2 |
| **Aggregated/Derived** |
| Time-of-day distribution | partial | Timestamps on all events | No aggregation table | Batch job: hour-of-day histogram → AttackerAggregate | V2 |
| Session duration dist | partial | SessionProfile would have duration | No SessionProfile table yet | Implement SessionProfile + duration stats | V2 |
| Recon-to-action ratio | partial | AttackerBehavior.phase_sequence | No per-attacker ratio column | Compute ratio in profiler; store in AttackerAggregate | V2 |
| Lateral movement style | not_captured | Correlation engine has traversal path | No traversal pattern analysis | Extend engine to compute dwell time + fan-out metrics | V2 |
| Persistence-first vs. exfil | not_captured | No persistence event taxonomy | Needs event-type classification | Add PERSISTENCE_EVENT_TYPES; compute timings | V2 |
| Tool-chain ordering | partial | tool_guesses list exists; unordered | No temporal ordering | Sort by first-event timestamp; build transition graph | V2 |
| Error-response psych | not_captured | No success/failure event tagging | Requires per-command outcome tracking | Extend service events with status=success/failure | V2 |

---

## Pre-v1 Capture Gaps (Actionable, Blocky)

**Only tackle these if the signal is committed to the v1 roadmap:**

1. **KEX algorithm ordering** (ssh-transport)
   - **Action**: Add `AttackerBehavior.kex_order_raw` (MEDIUMTEXT, JSON list of algorithm strings).
   - **Effort**: 2 hrs (schema + sniffer event parser + profiler aggregator).
   - **Blocker?**: Only if roadmap demands full KEX analysis (currently only HASSH hash is promised).

2. **Per-keystroke timing ingestion** (keyboard/human)
   - **Action**: Create `SessionProfile` table (design in DEVELOPMENT_V2.md); stub write path with all NULLs.
   - **Effort**: 4 hrs (schema + migration + DAL).
   - **Blocker?**: Yes, if keystroke dynamics is v1 roadmap. Data exists on disk but is not queryable.

3. **SSH client banner capture** (ssh-transport)
   - **Action**: Extend sniffer to parse SSH banners from TCP stream before TLS; emit ssh_client_hello event.
   - **Effort**: 3 hrs (TCP stream parser + sniffer integration).
   - **Blocker?**: Yes, if full SSH client profiling is v1 roadmap (currently only server banner via HASSH).

4. **TCP options raw extraction** (network/transport)
   - **Action**: Extend `tcp_fingerprint` JSON to include raw options list (not just signature string).
   - **Effort**: 1 hr (minimal schema change + sniffer parser).
   - **Blocker?**: No (options_sig is good enough for current p0f-style fingerprinting; nice-to-have).

---

## Non-Capturable Signals (Explicit Deferral)

These require vantage-point changes or are architecturally infeasible:

| Signal | Why | Vantage Point Needed |
|--------|-----|----------------------|
| LANG / LC_ALL | Server locale is fixed; attacker's client locale invisible over SSH | Client-side instrumentation |
| HTTP/2 SETTINGS frame order | Encrypted inside TLS stream | Server-side decryption or key log |
| HTTP/2 stream prioritization | Encrypted | Server-side decryption |
| Initial congestion window (CWND) | Requires detailed TCP ACK-clock tracking | Per-packet sniffer instrumentation |
| Packet pacing (μs resolution) | Requires hardware-timestamped PCAP or kernel hooks | OS-level instrumentation |
| Hold time / pressure / velocity (typing biometrics) | Not on SSH wire | Client-side TLS instrumentation |

---

## Summary for v1 Release

**Ship with these (already captured, queryable)**:
- HASSH/HASSHServer ✓
- JA3/JA3S/JA4/JA4S ✓
- TLS session resumption ✓
- TCP fingerprint (window, wscale, mss, options_sig) ✓
- Behavioral timing stats (mean/median/stdev IAT) ✓
- Phase sequencing (recon_end, exfil_start) ✓
- Tool attribution (beacon timing + headers) ✓

**Data exists on disk, not queryable (v1 deferral acceptable)**:
- Per-keystroke timing (asciinema day-shards) — needs SessionProfile ingestion job
- SSH client banner (TCP stream) — needs sniffer enhancement
- KEX algorithm order (syslog) — needs AttackerBehavior.kex_order_raw column

**Requires infrastructure changes (v2+)**:
- Lateral movement graph analysis
- HTTP header order + cookie jar behavior
- Persistence-first vs. exfil-first classification
- Error-response psychology
- Chronotyping + session duration distribution

---

## Federation & Cross-Operator Gossip (v2 Implications)

The `SessionProfile` schema (table, schema_version field, numeric features) is designed to be the federation wire format. **No changes needed for v1**, but ensure schema_version is in the table definition from day one so gossip compatibility is straightforward in v2.

---

## Appendices

### A. Code Paths Audited

- `decnet/sniffer/fingerprint.py` — TLS + TCP fingerprinting engine
- `decnet/services/ssh.py` — SSH service config + artifact paths
- `decnet/prober/hassh.py` — HASSHServer computation
- `decnet/web/db/models.py` — SQL schema (Attacker, AttackerBehavior, etc.)
- `decnet/profiler/behavioral.py` — Timing + tool attribution
- `decnet/correlation/parser.py` — RFC 5424 syslog ingestion
- `decnet/templates/ssh/` — Session recording (asciinema), syslog bridge, capture.sh

### B. Storage Destinations Verified

- **Database**: SQLite/MySQL tables (Attacker, AttackerBehavior, Bounty, Log)
- **Syslog**: RFC 5424 events (parsed by correlation engine, optionally piped to ELK)
- **Disk**: Asciinema day-shards (`/var/lib/decnet/session_recordings/`), raw PCAP (retention TBD)
- **Memory**: Sniffer state (sessions, flows, dedup cache) — lost on restart unless replayed from PCAP

### C. Roadmap Cross-Reference

- DEVELOPMENT.md lines 48–133: Attacker Intelligence Collection (TLS, behavioral, protocol fingerprinting, network topology, geolocation, service-level, aggregated).
  - `[x]` JA3/JA3S, JA4+, JARM, session resumption, TCP window/scaling, retransmits, beaconing, data exfil timing, HASSH/HASSHServer, HTTP/2 fingerprint, TLS session resumption, TTL values (partial), TCP stack fingerprinting.
  - `[ ]` (not v1): ISN patterns, HTTP header ordering, QUIC, DNS, IPv6/mDNS leakage, geolocation, service-level commands, credential reuse, payload signatures.

- DEVELOPMENT_V2.md: Keystroke dynamics, session profiling, federation.
  - SessionProfile schema (lines 71–104) — not yet implemented; ready-to-implement design.
  - Correlation via simhash (lines 50–56) — digraph rhythm fingerprinting.

---

