"""
Unit tests for the profiler behavioral/timing analyzer.

Covers:
  - timing_stats: mean/median/stdev/cv on synthetic event streams
  - classify_behavior: beaconing vs interactive vs scanning vs mixed vs unknown
  - guess_tool: attribution matching and tolerance boundaries
  - phase_sequence: recon → exfil latency detection
  - sniffer_rollup: OS-guess mode, hop median, retransmit sum
  - build_behavior_record: composite output shape (JSON-encoded subfields)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from decnet.correlation.parser import LogEvent
from decnet.profiler.behavioral import (
    build_behavior_record,
    classify_behavior,
    guess_tool,
    phase_sequence,
    sniffer_rollup,
    timing_stats,
)


# ─── Helpers ────────────────────────────────────────────────────────────────

_BASE = datetime(2026, 4, 15, 12, 0, 0, tzinfo=timezone.utc)


def _mk(
    ts_offset_s: float,
    event_type: str = "connection",
    service: str = "ssh",
    decky: str = "decky-01",
    fields: dict | None = None,
    ip: str = "10.0.0.7",
) -> LogEvent:
    """Build a synthetic LogEvent at BASE + offset seconds."""
    return LogEvent(
        timestamp=_BASE + timedelta(seconds=ts_offset_s),
        decky=decky,
        service=service,
        event_type=event_type,
        attacker_ip=ip,
        fields=fields or {},
        raw="",
    )


def _regular_beacon(count: int, interval_s: float, jitter_s: float = 0.0) -> list[LogEvent]:
    """
    Build *count* events with alternating IATs of (interval_s ± jitter_s).

    This yields:
      - mean IAT = interval_s
      - stdev IAT = jitter_s
      - coefficient of variation = jitter_s / interval_s
    """
    events: list[LogEvent] = []
    offset = 0.0
    events.append(_mk(offset))
    for i in range(1, count):
        iat = interval_s + (jitter_s if i % 2 == 1 else -jitter_s)
        offset += iat
        events.append(_mk(offset))
    return events


# ─── timing_stats ───────────────────────────────────────────────────────────

class TestTimingStats:
    def test_empty_returns_nulls(self):
        s = timing_stats([])
        assert s["event_count"] == 0
        assert s["mean_iat_s"] is None
        assert s["cv"] is None

    def test_single_event(self):
        s = timing_stats([_mk(0)])
        assert s["event_count"] == 1
        assert s["duration_s"] == 0.0
        assert s["mean_iat_s"] is None

    def test_regular_cadence_cv_is_zero(self):
        events = _regular_beacon(count=10, interval_s=60.0)
        s = timing_stats(events)
        assert s["event_count"] == 10
        assert s["mean_iat_s"] == 60.0
        assert s["cv"] == 0.0
        assert s["stdev_iat_s"] == 0.0

    def test_jittered_cadence(self):
        events = _regular_beacon(count=20, interval_s=60.0, jitter_s=12.0)
        s = timing_stats(events)
        # Mean is close to 60, cv ~20% (jitter 12 / interval 60)
        assert abs(s["mean_iat_s"] - 60.0) < 2.0
        assert s["cv"] is not None
        assert 0.10 < s["cv"] < 0.50


# ─── classify_behavior ──────────────────────────────────────────────────────

class TestClassifyBehavior:
    def test_unknown_if_too_few(self):
        s = timing_stats(_regular_beacon(count=2, interval_s=60.0))
        assert classify_behavior(s, services_count=1) == "unknown"

    def test_beaconing_regular_cadence(self):
        s = timing_stats(_regular_beacon(count=10, interval_s=60.0, jitter_s=3.0))
        assert classify_behavior(s, services_count=1) == "beaconing"

    def test_interactive_fast_irregular(self):
        # Very fast events with high variance ≈ a human hitting keys + think time
        events = []
        times = [0, 0.2, 0.5, 1.0, 5.0, 5.1, 5.3, 10.0, 10.1, 10.2, 12.0]
        for t in times:
            events.append(_mk(t))
        s = timing_stats(events)
        assert classify_behavior(s, services_count=1) == "interactive"

    def test_scanning_many_services_fast(self):
        # 10 events across 5 services, each 0.2s apart
        events = []
        svcs = ["ssh", "http", "smb", "ftp", "rdp"]
        for i in range(10):
            events.append(_mk(i * 0.2, service=svcs[i % 5]))
        s = timing_stats(events)
        assert classify_behavior(s, services_count=5) == "scanning"

    def test_mixed_fallback(self):
        # Moderate count, moderate cv, single service, moderate cadence
        events = _regular_beacon(count=6, interval_s=20.0, jitter_s=10.0)
        s = timing_stats(events)
        # cv ~0.5, not tight enough for beaconing, mean 20s > interactive
        result = classify_behavior(s, services_count=1)
        assert result in ("mixed", "interactive")  # either is acceptable


# ─── guess_tool ─────────────────────────────────────────────────────────────

class TestGuessTool:
    def test_cobalt_strike(self):
        # Default: 60s interval, 20% jitter → cv 0.20
        assert guess_tool(mean_iat_s=60.0, cv=0.20) == "cobalt_strike"

    def test_havoc(self):
        # 45s interval, 10% jitter → cv 0.10
        assert guess_tool(mean_iat_s=45.0, cv=0.10) == "havoc"

    def test_mythic(self):
        assert guess_tool(mean_iat_s=30.0, cv=0.15) == "mythic"

    def test_no_match_outside_tolerance(self):
        # 5-second beacon is far from any default
        assert guess_tool(mean_iat_s=5.0, cv=0.10) is None

    def test_none_when_stats_missing(self):
        assert guess_tool(None, None) is None
        assert guess_tool(60.0, None) is None

    def test_ambiguous_returns_none(self):
        # If a signature set is tweaked such that two profiles overlap,
        # guess_tool must not attribute.
        # Cobalt (60±10s, cv 0.20±0.08) and Sliver (60±15s, cv 0.30±0.10)
        # overlap around (60s, cv=0.25). Both match → None.
        result = guess_tool(mean_iat_s=60.0, cv=0.25)
        assert result is None


# ─── phase_sequence ────────────────────────────────────────────────────────

class TestPhaseSequence:
    def test_recon_then_exfil(self):
        events = [
            _mk(0, event_type="scan"),
            _mk(10, event_type="login_attempt"),
            _mk(20, event_type="auth_failure"),
            _mk(120, event_type="exec"),
            _mk(150, event_type="download"),
        ]
        p = phase_sequence(events)
        assert p["recon_end_ts"] is not None
        assert p["exfil_start_ts"] is not None
        assert p["exfil_latency_s"] == 100.0  # 120 - 20

    def test_no_exfil(self):
        events = [_mk(0, event_type="scan"), _mk(10, event_type="scan")]
        p = phase_sequence(events)
        assert p["exfil_start_ts"] is None
        assert p["exfil_latency_s"] is None

    def test_large_payload_counted(self):
        events = [
            _mk(0, event_type="download", fields={"bytes": "2097152"}),  # 2 MiB
            _mk(10, event_type="download", fields={"bytes": "500"}),     # small
            _mk(20, event_type="upload",   fields={"size": "10485760"}), # 10 MiB
        ]
        p = phase_sequence(events)
        assert p["large_payload_count"] == 2


# ─── sniffer_rollup ─────────────────────────────────────────────────────────

class TestSnifferRollup:
    def test_os_mode(self):
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "linux", "hop_distance": "3",
                        "window": "29200", "mss": "1460"}),
            _mk(5, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "linux", "hop_distance": "3",
                        "window": "29200", "mss": "1460"}),
            _mk(10, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "windows", "hop_distance": "8",
                        "window": "64240", "mss": "1460"}),
        ]
        r = sniffer_rollup(events)
        assert r["os_guess"] == "linux"  # mode
        # Median of [3, 3, 8] = 3
        assert r["hop_distance"] == 3
        # Latest fingerprint snapshot wins
        assert r["tcp_fingerprint"]["window"] == 64240

    def test_retransmits_summed(self):
        events = [
            _mk(0, event_type="tcp_flow_timing", fields={"retransmits": "2"}),
            _mk(10, event_type="tcp_flow_timing", fields={"retransmits": "5"}),
            _mk(20, event_type="tcp_flow_timing", fields={"retransmits": "0"}),
        ]
        r = sniffer_rollup(events)
        assert r["retransmit_count"] == 7

    def test_empty(self):
        r = sniffer_rollup([])
        assert r["os_guess"] is None
        assert r["hop_distance"] is None
        assert r["retransmit_count"] == 0


# ─── build_behavior_record (composite) ──────────────────────────────────────

class TestBuildBehaviorRecord:
    def test_beaconing_with_cobalt_strike_match(self):
        # 60s interval, 20% jitter → cobalt strike default
        events = _regular_beacon(count=20, interval_s=60.0, jitter_s=12.0)
        r = build_behavior_record(events)
        assert r["behavior_class"] == "beaconing"
        assert r["beacon_interval_s"] is not None
        assert 50 < r["beacon_interval_s"] < 70
        assert r["beacon_jitter_pct"] is not None
        assert r["tool_guess"] == "cobalt_strike"

    def test_json_fields_are_strings(self):
        events = _regular_beacon(count=5, interval_s=60.0)
        r = build_behavior_record(events)
        # timing_stats, phase_sequence, tcp_fingerprint must be JSON strings
        assert isinstance(r["timing_stats"], str)
        json.loads(r["timing_stats"])  # doesn't raise
        assert isinstance(r["phase_sequence"], str)
        json.loads(r["phase_sequence"])
        assert isinstance(r["tcp_fingerprint"], str)
        json.loads(r["tcp_fingerprint"])

    def test_non_beaconing_has_null_beacon_fields(self):
        # Scanning behavior — should not report a beacon interval
        events = []
        svcs = ["ssh", "http", "smb", "ftp", "rdp"]
        for i in range(10):
            events.append(_mk(i * 0.2, service=svcs[i % 5]))
        r = build_behavior_record(events)
        assert r["behavior_class"] == "scanning"
        assert r["beacon_interval_s"] is None
        assert r["beacon_jitter_pct"] is None
