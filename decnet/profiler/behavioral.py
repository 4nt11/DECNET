"""
Behavioral and timing analysis for DECNET attacker profiles.

Consumes the chronological `LogEvent` stream already built by
`decnet.correlation.engine.CorrelationEngine` and derives per-IP metrics:

  - Inter-event timing statistics (mean / median / stdev / min / max)
  - Coefficient-of-variation (jitter metric)
  - Beaconing vs. interactive vs. scanning classification
  - Tool attribution against known C2 frameworks (Cobalt Strike, Sliver,
    Havoc, Mythic) using default beacon/jitter profiles
  - Recon → exfil phase sequencing (latency between the last recon event
    and the first exfil-like event)
  - OS / TCP fingerprint + retransmit rollup from sniffer-emitted events

Pure-Python; no external dependencies. All functions are safe to call from
both sync and async contexts.
"""

from __future__ import annotations

import json
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

# ─── C2 tool attribution signatures ─────────────────────────────────────────
#
# Each entry lists the default beacon cadence profile of a popular C2.
# A profile *matches* an attacker when:
#   - mean inter-event time is within ±`interval_tolerance` seconds, AND
#   - jitter (cv = stdev / mean) is within ±`jitter_tolerance`
#
# These defaults are documented in each framework's public user guides;
# real operators often tune them, so attribution is advisory, not definitive.

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
    Coarse behavior bucket: beaconing | interactive | scanning | mixed | unknown

    Heuristics:
      * `beaconing`   — low CV (< 0.35) + mean IAT ≥ 5 s + ≥ 5 events
      * `scanning`    — ≥ 3 services touched in short bursts (mean IAT < 3 s)
      * `interactive` — fast but irregular: mean IAT < 3 s AND CV ≥ 0.5, ≥ 10 events
      * `mixed`       — moderate count + moderate CV, neither cleanly beaconing nor interactive
      * `unknown`     — too few data points
    """
    n = stats.get("event_count") or 0
    mean = stats.get("mean_iat_s")
    cv = stats.get("cv")

    if n < 3 or mean is None:
        return "unknown"

    # Scanning: many services, fast bursts, few events per service.
    if services_count >= 3 and mean < 3.0 and n >= 5:
        return "scanning"

    # Beaconing: regular cadence over many events.
    if cv is not None and cv < 0.35 and mean >= 5.0 and n >= 5:
        return "beaconing"

    # Interactive: short, irregular intervals.
    if cv is not None and cv >= 0.5 and mean < 3.0 and n >= 10:
        return "interactive"

    return "mixed"


# ─── C2 tool attribution ────────────────────────────────────────────────────

def guess_tool(mean_iat_s: float | None, cv: float | None) -> str | None:
    """
    Match (mean_iat, cv) against known C2 default beacon profiles.

    Returns the tool name if a single signature matches; None otherwise.
    Multiple matches also return None to avoid false attribution.
    """
    if mean_iat_s is None or cv is None:
        return None

    hits: list[str] = []
    for sig in _TOOL_SIGNATURES:
        if abs(mean_iat_s - sig["interval_s"]) > sig["interval_tolerance_s"]:
            continue
        if abs(cv - sig["jitter_cv"]) > sig["jitter_tolerance"]:
            continue
        hits.append(sig["name"])

    if len(hits) == 1:
        return hits[0]
    return None


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
    """
    os_guesses: list[str] = []
    hops: list[int] = []
    tcp_fp: dict[str, Any] | None = None
    retransmits = 0

    for e in events:
        if e.event_type == _SNIFFER_SYN_EVENT:
            og = e.fields.get("os_guess")
            if og:
                os_guesses.append(og)
            try:
                hops.append(int(e.fields.get("hop_distance", "0")))
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
    tool = guess_tool(stats.get("mean_iat_s"), stats.get("cv"))
    phase = phase_sequence(events)
    rollup = sniffer_rollup(events)

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
        "tool_guess": tool,
        "timing_stats": json.dumps(stats),
        "phase_sequence": json.dumps(phase),
    }
