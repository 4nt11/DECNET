"""
Behavioral and timing analysis for DECNET attacker profiles.

Consumes the chronological `LogEvent` stream already built by
`decnet.correlation.engine.CorrelationEngine` and derives per-IP metrics:

  - Inter-event timing statistics (mean / median / stdev / min / max)
  - Coefficient-of-variation (jitter metric)
  - Beaconing vs. interactive vs. scanning vs. brute_force vs. slow_scan
    classification
  - Tool attribution against known C2 frameworks (Cobalt Strike, Sliver,
    Havoc, Mythic) using default beacon/jitter profiles — returns a list,
    since multiple tools can be in use simultaneously
  - Header-based tool detection (Nmap NSE, Gophish, Nikto, sqlmap, etc.)
    from HTTP request events
  - Recon → exfil phase sequencing (latency between the last recon event
    and the first exfil-like event)
  - OS / TCP fingerprint + retransmit rollup from sniffer-emitted events,
    with TTL-based fallback when p0f returns no match

Pure-Python; no external dependencies. All functions are safe to call from
both sync and async contexts.
"""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from typing import Any

from decnet.correlation.parser import LogEvent

# ─── Event-type taxonomy ────────────────────────────────────────────────────

# Sniffer-emitted packet events that feed into fingerprint rollup.
_SNIFFER_SYN_EVENT: str = "tcp_syn_fingerprint"
_SNIFFER_FLOW_EVENT: str = "tcp_flow_timing"

# Events that signal "recon" phase (scans, probes, auth attempts).
_RECON_EVENT_TYPES: frozenset[str] = frozenset({
    "scan", "connection", "banner", "probe",
    "login_attempt", "auth", "auth_failure",
})

# Events that signal "exfil" / action-on-objective phase.
_EXFIL_EVENT_TYPES: frozenset[str] = frozenset({
    "download", "upload", "file_transfer", "data_exfil",
    "command", "exec", "query", "shell_input",
})

# Fields carrying payload byte counts (for "large payload" detection).
_PAYLOAD_SIZE_FIELDS: tuple[str, ...] = ("bytes", "size", "content_length")

# ─── C2 tool attribution signatures (beacon timing) ─────────────────────────
#
# Each entry lists the default beacon cadence profile of a popular C2.
# A profile *matches* an attacker when:
#   - mean inter-event time is within ±`interval_tolerance` seconds, AND
#   - jitter (cv = stdev / mean) is within ±`jitter_tolerance`
#
# Multiple matches are all returned (attacker may run multiple implants).

_TOOL_SIGNATURES: tuple[dict[str, Any], ...] = (
    {
        "name": "cobalt_strike",
        "interval_s": 60.0,
        "interval_tolerance_s": 8.0,
        "jitter_cv": 0.20,
        "jitter_tolerance": 0.05,
    },
    {
        "name": "sliver",
        "interval_s": 60.0,
        "interval_tolerance_s": 10.0,
        "jitter_cv": 0.30,
        "jitter_tolerance": 0.08,
    },
    {
        "name": "havoc",
        "interval_s": 45.0,
        "interval_tolerance_s": 8.0,
        "jitter_cv": 0.10,
        "jitter_tolerance": 0.03,
    },
    {
        "name": "mythic",
        "interval_s": 30.0,
        "interval_tolerance_s": 6.0,
        "jitter_cv": 0.15,
        "jitter_tolerance": 0.03,
    },
)

# ─── Header-based tool signatures ───────────────────────────────────────────
#
# Scanned against HTTP `request` events.  `pattern` is a case-insensitive
# substring (or a regex anchored with ^ if it starts with that character).
# `header` is matched case-insensitively against the event's headers dict.

_HEADER_TOOL_SIGNATURES: tuple[dict[str, str], ...] = (
    {"name": "nmap",             "header": "user-agent", "pattern": "Nmap Scripting Engine"},
    {"name": "gophish",          "header": "x-mailer",   "pattern": "gophish"},
    {"name": "nikto",            "header": "user-agent", "pattern": "Nikto"},
    {"name": "sqlmap",           "header": "user-agent", "pattern": "sqlmap"},
    {"name": "nuclei",           "header": "user-agent", "pattern": "Nuclei"},
    {"name": "masscan",          "header": "user-agent", "pattern": "masscan"},
    {"name": "zgrab",            "header": "user-agent", "pattern": "zgrab"},
    {"name": "metasploit",       "header": "user-agent", "pattern": "Metasploit"},
    {"name": "curl",             "header": "user-agent", "pattern": "^curl/"},
    {"name": "python_requests",  "header": "user-agent", "pattern": "python-requests"},
    {"name": "gobuster",         "header": "user-agent", "pattern": "gobuster"},
    {"name": "dirbuster",        "header": "user-agent", "pattern": "DirBuster"},
    {"name": "hydra",            "header": "user-agent", "pattern": "hydra"},
    {"name": "wfuzz",            "header": "user-agent", "pattern": "Wfuzz"},
)

# ─── TTL → coarse OS bucket (fallback when p0f returns nothing) ─────────────

def _os_from_ttl(ttl_str: str | None) -> str | None:
    """Derive a coarse OS guess from observed TTL when p0f has no match."""
    if not ttl_str:
        return None
    try:
        ttl = int(ttl_str)
    except (TypeError, ValueError):
        return None
    if 55 <= ttl <= 70:
        return "linux"
    if 115 <= ttl <= 135:
        return "windows"
    if 235 <= ttl <= 255:
        return "embedded"
    return None


# ─── Timing stats ───────────────────────────────────────────────────────────

def timing_stats(events: list[LogEvent]) -> dict[str, Any]:
    """
    Compute inter-arrival-time statistics across *events* (sorted by ts).

    Returns a dict with:
      mean_iat_s, median_iat_s, stdev_iat_s, min_iat_s, max_iat_s, cv,
      event_count, duration_s

    For n < 2 events the interval-based fields are None/0.
    """
    if not events:
        return {
            "event_count": 0,
            "duration_s": 0.0,
            "mean_iat_s": None,
            "median_iat_s": None,
            "stdev_iat_s": None,
            "min_iat_s": None,
            "max_iat_s": None,
            "cv": None,
        }

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    duration_s = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()

    if len(sorted_events) < 2:
        return {
            "event_count": len(sorted_events),
            "duration_s": round(duration_s, 3),
            "mean_iat_s": None,
            "median_iat_s": None,
            "stdev_iat_s": None,
            "min_iat_s": None,
            "max_iat_s": None,
            "cv": None,
        }

    iats = [
        (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
        for i in range(1, len(sorted_events))
    ]
    # Exclude spuriously-negative (clock-skew) intervals.
    iats = [v for v in iats if v >= 0]
    if not iats:
        return {
            "event_count": len(sorted_events),
            "duration_s": round(duration_s, 3),
            "mean_iat_s": None,
            "median_iat_s": None,
            "stdev_iat_s": None,
            "min_iat_s": None,
            "max_iat_s": None,
            "cv": None,
        }

    mean = statistics.fmean(iats)
    median = statistics.median(iats)
    stdev = statistics.pstdev(iats) if len(iats) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else None

    return {
        "event_count": len(sorted_events),
        "duration_s": round(duration_s, 3),
        "mean_iat_s": round(mean, 3),
        "median_iat_s": round(median, 3),
        "stdev_iat_s": round(stdev, 3),
        "min_iat_s": round(min(iats), 3),
        "max_iat_s": round(max(iats), 3),
        "cv": round(cv, 4) if cv is not None else None,
    }


# ─── Behavior classification ────────────────────────────────────────────────

def classify_behavior(stats: dict[str, Any], services_count: int) -> str:
    """
    Coarse behavior bucket:
      beaconing | interactive | scanning | brute_force | slow_scan | mixed | unknown

    Heuristics (evaluated in priority order):
      * `scanning`    — ≥ 3 services touched OR mean IAT < 2 s, ≥ 3 events
      * `brute_force` — 1 service, n ≥ 8, mean IAT < 5 s, CV < 0.6
      * `beaconing`   — CV < 0.35, mean IAT ≥ 5 s, ≥ 4 events
      * `slow_scan`   — ≥ 2 services, mean IAT ≥ 10 s, ≥ 4 events
      * `interactive` — mean IAT < 5 s AND CV ≥ 0.5, ≥ 6 events
      * `mixed`       — catch-all for sessions with enough data
      * `unknown`     — too few data points
    """
    n = stats.get("event_count") or 0
    mean = stats.get("mean_iat_s")
    cv = stats.get("cv")

    if n < 3 or mean is None:
        return "unknown"

    # Slow scan / low-and-slow: multiple services with long gaps.
    # Must be checked before generic scanning so slow multi-service sessions
    # don't get mis-bucketed as a fast sweep.
    if services_count >= 2 and mean >= 10.0 and n >= 4:
        return "slow_scan"

    # Scanning: broad service sweep (multi-service) or very rapid single-service bursts.
    if n >= 3 and (
        (services_count >= 3 and mean < 10.0)
        or (services_count >= 2 and mean < 2.0)
    ):
        return "scanning"

    # Brute force: hammering one service rapidly and repeatedly.
    if services_count == 1 and n >= 8 and mean < 5.0 and cv is not None and cv < 0.6:
        return "brute_force"

    # Beaconing: regular cadence over multiple events.
    if cv is not None and cv < 0.35 and mean >= 5.0 and n >= 4:
        return "beaconing"

    # Interactive: short but irregular bursts (human or tool with think time).
    if cv is not None and cv >= 0.5 and mean < 5.0 and n >= 6:
        return "interactive"

    return "mixed"


# ─── C2 tool attribution (beacon timing) ────────────────────────────────────

def guess_tools(mean_iat_s: float | None, cv: float | None) -> list[str]:
    """
    Match (mean_iat, cv) against known C2 default beacon profiles.

    Returns a list of all matching tool names (may be empty).  Multiple
    matches are all returned because an attacker can run several implants.
    """
    if mean_iat_s is None or cv is None:
        return []

    hits: list[str] = []
    for sig in _TOOL_SIGNATURES:
        if abs(mean_iat_s - sig["interval_s"]) > sig["interval_tolerance_s"]:
            continue
        if abs(cv - sig["jitter_cv"]) > sig["jitter_tolerance"]:
            continue
        hits.append(sig["name"])

    return hits


# Keep the old name as an alias so callers that expected a single string still
# compile, but mark it deprecated.  Returns the first hit or None.
def guess_tool(mean_iat_s: float | None, cv: float | None) -> str | None:
    """Deprecated: use guess_tools() instead."""
    hits = guess_tools(mean_iat_s, cv)
    if len(hits) == 1:
        return hits[0]
    return None


# ─── Header-based tool detection ────────────────────────────────────────────

def detect_tools_from_headers(events: list[LogEvent]) -> list[str]:
    """
    Scan HTTP `request` events for tool-identifying headers.

    Checks User-Agent, X-Mailer, and other headers case-insensitively
    against `_HEADER_TOOL_SIGNATURES`.  Returns a deduplicated list of
    matched tool names in detection order.
    """
    found: list[str] = []
    seen: set[str] = set()

    for e in events:
        if e.event_type != "request":
            continue

        raw_headers = e.fields.get("headers")
        if not raw_headers:
            continue

        # headers may arrive as a JSON string or a dict already
        if isinstance(raw_headers, str):
            try:
                headers: dict[str, str] = json.loads(raw_headers)
            except (json.JSONDecodeError, ValueError):
                continue
        elif isinstance(raw_headers, dict):
            headers = raw_headers
        else:
            continue

        # Normalise header keys to lowercase for matching.
        lc_headers: dict[str, str] = {k.lower(): str(v) for k, v in headers.items()}

        for sig in _HEADER_TOOL_SIGNATURES:
            name = sig["name"]
            if name in seen:
                continue
            value = lc_headers.get(sig["header"])
            if value is None:
                continue
            pattern = sig["pattern"]
            if pattern.startswith("^"):
                if re.match(pattern, value, re.IGNORECASE):
                    found.append(name)
                    seen.add(name)
            else:
                if pattern.lower() in value.lower():
                    found.append(name)
                    seen.add(name)

    return found


# ─── Phase sequencing ───────────────────────────────────────────────────────

def phase_sequence(events: list[LogEvent]) -> dict[str, Any]:
    """
    Derive recon→exfil phase transition info.

    Returns:
      recon_end_ts       : ISO timestamp of last recon-class event (or None)
      exfil_start_ts     : ISO timestamp of first exfil-class event (or None)
      exfil_latency_s    : seconds between them (None if not both present)
      large_payload_count: count of events whose *fields* report a payload
                           ≥ 1 MiB (heuristic for bulk data transfer)
    """
    recon_end = None
    exfil_start = None
    large_payload_count = 0

    for e in sorted(events, key=lambda x: x.timestamp):
        if e.event_type in _RECON_EVENT_TYPES:
            recon_end = e.timestamp
        elif e.event_type in _EXFIL_EVENT_TYPES and exfil_start is None:
            exfil_start = e.timestamp

        for fname in _PAYLOAD_SIZE_FIELDS:
            raw = e.fields.get(fname)
            if raw is None:
                continue
            try:
                if int(raw) >= 1_048_576:
                    large_payload_count += 1
                    break
            except (TypeError, ValueError):
                continue

    latency: float | None = None
    if recon_end is not None and exfil_start is not None and exfil_start >= recon_end:
        latency = round((exfil_start - recon_end).total_seconds(), 3)

    return {
        "recon_end_ts": recon_end.isoformat() if recon_end else None,
        "exfil_start_ts": exfil_start.isoformat() if exfil_start else None,
        "exfil_latency_s": latency,
        "large_payload_count": large_payload_count,
    }


# ─── Sniffer rollup (OS fingerprint + retransmits) ──────────────────────────

def sniffer_rollup(events: list[LogEvent]) -> dict[str, Any]:
    """
    Roll up sniffer-emitted `tcp_syn_fingerprint` and `tcp_flow_timing`
    events into a per-attacker summary.

    OS guess priority:
      1. Modal p0f label from os_guess field (if not "unknown"/empty).
      2. TTL-based coarse bucket (linux / windows / embedded) as fallback.
    Hop distance: median of non-zero reported values only.
    """
    os_guesses: list[str] = []
    ttl_values: list[str] = []
    hops: list[int] = []
    tcp_fp: dict[str, Any] | None = None
    retransmits = 0

    for e in events:
        if e.event_type == _SNIFFER_SYN_EVENT:
            og = e.fields.get("os_guess")
            if og and og != "unknown":
                os_guesses.append(og)

            # Collect raw TTL for fallback OS derivation.
            ttl_raw = e.fields.get("ttl") or e.fields.get("initial_ttl")
            if ttl_raw:
                ttl_values.append(ttl_raw)

            # Only include hop distances that are valid and non-zero.
            hop_raw = e.fields.get("hop_distance")
            if hop_raw:
                try:
                    hop_val = int(hop_raw)
                    if hop_val > 0:
                        hops.append(hop_val)
                except (TypeError, ValueError):
                    pass

            # Keep the latest fingerprint snapshot.
            tcp_fp = {
                "window": _int_or_none(e.fields.get("window")),
                "wscale": _int_or_none(e.fields.get("wscale")),
                "mss": _int_or_none(e.fields.get("mss")),
                "options_sig": e.fields.get("options_sig", ""),
                "has_sack": e.fields.get("has_sack") == "true",
                "has_timestamps": e.fields.get("has_timestamps") == "true",
            }

        elif e.event_type == _SNIFFER_FLOW_EVENT:
            try:
                retransmits += int(e.fields.get("retransmits", "0"))
            except (TypeError, ValueError):
                pass

    # Mode for the OS bucket — most frequently observed label.
    os_guess: str | None = None
    if os_guesses:
        os_guess = Counter(os_guesses).most_common(1)[0][0]
    else:
        # TTL-based fallback: use the most common observed TTL value.
        if ttl_values:
            modal_ttl = Counter(ttl_values).most_common(1)[0][0]
            os_guess = _os_from_ttl(modal_ttl)

    # Median hop distance (robust to the occasional weird TTL).
    hop_distance: int | None = None
    if hops:
        hop_distance = int(statistics.median(hops))

    return {
        "os_guess": os_guess,
        "hop_distance": hop_distance,
        "tcp_fingerprint": tcp_fp or {},
        "retransmit_count": retransmits,
    }


def _int_or_none(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ─── Composite: build the full AttackerBehavior record ──────────────────────

def build_behavior_record(events: list[LogEvent]) -> dict[str, Any]:
    """
    Build the dict to persist in the `attacker_behavior` table.

    Callers (profiler worker) pre-serialize JSON-typed fields; we do the
    JSON encoding here to keep the repo layer schema-agnostic.
    """
    # Timing stats are computed across *all* events (not filtered), because
    # a C2 beacon often reuses the same "connection" event_type on each
    # check-in. Filtering would throw that signal away.
    stats = timing_stats(events)
    services = {e.service for e in events}
    behavior = classify_behavior(stats, len(services))
    rollup = sniffer_rollup(events)
    phase = phase_sequence(events)

    # Combine beacon-timing tool matches with header-based detections.
    beacon_tools = guess_tools(stats.get("mean_iat_s"), stats.get("cv"))
    header_tools = detect_tools_from_headers(events)
    all_tools: list[str] = list(dict.fromkeys(beacon_tools + header_tools))  # dedup, preserve order

    # Promote TCP-level scanner identification to tool_guesses.
    # p0f fingerprints nmap from the TCP handshake alone — this fires even
    # when no HTTP service is present, making it far more reliable than the
    # header-based path for raw port scans.
    if rollup["os_guess"] == "nmap" and "nmap" not in all_tools:
        all_tools.insert(0, "nmap")

    # Beacon-specific projection: only surface interval/jitter when we've
    # classified the flow as beaconing (otherwise these numbers are noise).
    beacon_interval_s: float | None = None
    beacon_jitter_pct: float | None = None
    if behavior == "beaconing":
        beacon_interval_s = stats.get("mean_iat_s")
        cv = stats.get("cv")
        beacon_jitter_pct = round(cv * 100, 2) if cv is not None else None

    return {
        "os_guess": rollup["os_guess"],
        "hop_distance": rollup["hop_distance"],
        "tcp_fingerprint": json.dumps(rollup["tcp_fingerprint"]),
        "retransmit_count": rollup["retransmit_count"],
        "behavior_class": behavior,
        "beacon_interval_s": beacon_interval_s,
        "beacon_jitter_pct": beacon_jitter_pct,
        "tool_guesses": json.dumps(all_tools),
        "timing_stats": json.dumps(stats),
        "phase_sequence": json.dumps(phase),
    }
