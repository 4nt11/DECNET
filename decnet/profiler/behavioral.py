"""
Behavioral and timing analysis for DECNET attacker profiles.

This module is the orchestrator: it composes the topical sub-modules
(`timing`, `classify`, `tools`, `phases`, `fingerprint`) into the single
`attacker_behavior` record persisted by the profiler worker.

The individual detectors live in sibling modules:
  - `timing.py`      — inter-arrival-time statistics
  - `classify.py`    — behavior bucket (beaconing / scanning / …)
  - `tools.py`       — C2 beacon cadence + HTTP-header tool attribution
  - `phases.py`      — recon → exfil phase sequencing
  - `fingerprint.py` — sniffer + prober TCP/OS fingerprint rollup

Their public symbols are re-exported here for backward compatibility with
callers and tests that import directly from `decnet.profiler.behavioral`.
"""

from __future__ import annotations

import json
from typing import Any

from decnet.correlation.parser import LogEvent
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer

from .classify import classify_behavior
from .fingerprint import sniffer_rollup
from .phases import phase_sequence
from .timing import timing_stats
from .tools import detect_tools_from_headers, guess_tool, guess_tools

__all__ = [
    "build_behavior_record",
    "classify_behavior",
    "detect_tools_from_headers",
    "guess_tool",
    "guess_tools",
    "phase_sequence",
    "sniffer_rollup",
    "timing_stats",
]


@_traced("profiler.build_behavior_record")
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

    _tracer = _get_tracer("profiler")
    with _tracer.start_as_current_span("profiler.behavior_summary") as _span:
        _span.set_attribute("behavior_class", behavior)
        _span.set_attribute("os_guess", rollup["os_guess"] or "unknown")
        _span.set_attribute("tool_count", len(all_tools))
        _span.set_attribute("event_count", stats.get("event_count", 0))
        if all_tools:
            _span.set_attribute("tools", ",".join(all_tools))

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
