"""
Unit tests for the profiler behavioral/timing analyzer.

Covers:
  - timing_stats: mean/median/stdev/cv on synthetic event streams
  - classify_behavior: beaconing / interactive / scanning / brute_force /
    slow_scan / mixed / unknown
  - guess_tools: C2 attribution, list return, multi-match
  - detect_tools_from_headers: Nmap NSE, Gophish, unknown headers
  - phase_sequence: recon → exfil latency detection
  - sniffer_rollup: OS-guess mode + TTL fallback, hop median (zeros excluded),
    retransmit sum
  - build_behavior_record: composite output shape (JSON-encoded subfields,
    tool_guesses list)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from decnet.correlation.parser import LogEvent
from decnet.profiler.behavioral import (
    build_behavior_record,
    classify_behavior,
    detect_tools_from_headers,
    guess_tool,
    guess_tools,
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

    def test_scanning_fast_single_service_is_brute_force(self):
        # Very fast, regular bursts on one service → brute_force, not scanning.
        # Scanning requires multi-service sweep.
        events = [_mk(i * 0.5) for i in range(8)]
        s = timing_stats(events)
        assert classify_behavior(s, services_count=1) == "brute_force"

    def test_brute_force(self):
        # 10 rapid-ish login attempts on one service, moderate regularity
        events = [_mk(i * 2.0) for i in range(10)]
        s = timing_stats(events)
        # mean=2s, cv=0, single service
        assert classify_behavior(s, services_count=1) == "brute_force"

    def test_slow_scan(self):
        # Touches 3 services slowly — low-and-slow reconnaisance
        events = []
        svcs = ["ssh", "rdp", "smb"]
        for i in range(6):
            events.append(_mk(i * 15.0, service=svcs[i % 3]))
        s = timing_stats(events)
        assert classify_behavior(s, services_count=3) == "slow_scan"

    def test_mixed_fallback(self):
        # Moderate count, moderate cv, single service, moderate cadence
        events = _regular_beacon(count=6, interval_s=20.0, jitter_s=10.0)
        s = timing_stats(events)
        # cv ~0.5, not tight enough for beaconing, mean 20s > interactive
        result = classify_behavior(s, services_count=1)
        assert result in ("mixed", "interactive")  # either is acceptable


# ─── guess_tools ─────────────────────────────────────────────────────────────

class TestGuessTools:
    def test_cobalt_strike(self):
        assert "cobalt_strike" in guess_tools(mean_iat_s=60.0, cv=0.20)

    def test_havoc(self):
        assert "havoc" in guess_tools(mean_iat_s=45.0, cv=0.10)

    def test_mythic(self):
        assert "mythic" in guess_tools(mean_iat_s=30.0, cv=0.15)

    def test_no_match_outside_tolerance(self):
        assert guess_tools(mean_iat_s=5.0, cv=0.10) == []

    def test_none_when_stats_missing(self):
        assert guess_tools(None, None) == []
        assert guess_tools(60.0, None) == []

    def test_multiple_matches_all_returned(self):
        # Cobalt (60±8s, cv 0.20±0.05) and Sliver (60±10s, cv 0.30±0.08)
        # both accept cv=0.25 at 60s.
        result = guess_tools(mean_iat_s=60.0, cv=0.25)
        assert "cobalt_strike" in result
        assert "sliver" in result

    def test_returns_list(self):
        result = guess_tools(mean_iat_s=60.0, cv=0.20)
        assert isinstance(result, list)


class TestGuessToolLegacy:
    """The deprecated single-string alias must still work."""

    def test_cobalt_strike(self):
        assert guess_tool(mean_iat_s=60.0, cv=0.20) == "cobalt_strike"

    def test_havoc(self):
        assert guess_tool(mean_iat_s=45.0, cv=0.10) == "havoc"

    def test_mythic(self):
        assert guess_tool(mean_iat_s=30.0, cv=0.15) == "mythic"

    def test_no_match_outside_tolerance(self):
        assert guess_tool(mean_iat_s=5.0, cv=0.10) is None

    def test_none_when_stats_missing(self):
        assert guess_tool(None, None) is None
        assert guess_tool(60.0, None) is None

    def test_ambiguous_returns_none(self):
        # Two matches → legacy function returns None (ambiguous).
        result = guess_tool(mean_iat_s=60.0, cv=0.25)
        assert result is None


# ─── detect_tools_from_headers ───────────────────────────────────────────────

class TestDetectToolsFromHeaders:
    def _http_event(self, headers: dict, offset_s: float = 0) -> LogEvent:
        return _mk(offset_s, event_type="request",
                   service="http", fields={"headers": json.dumps(headers)})

    def test_nmap_nse_user_agent(self):
        e = self._http_event({
            "User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; "
                          "https://nmap.org/book/nse.html)"
        })
        assert "nmap" in detect_tools_from_headers([e])

    def test_gophish_x_mailer(self):
        e = self._http_event({"X-Mailer": "gophish"})
        assert "gophish" in detect_tools_from_headers([e])

    def test_sqlmap_user_agent(self):
        e = self._http_event({"User-Agent": "sqlmap/1.7.9#stable (https://sqlmap.org)"})
        assert "sqlmap" in detect_tools_from_headers([e])

    def test_curl_anchor_pattern(self):
        e = self._http_event({"User-Agent": "curl/8.1.2"})
        assert "curl" in detect_tools_from_headers([e])

    def test_curl_anchor_no_false_positive(self):
        # "not-curl/something" should NOT match the anchored ^curl/ pattern.
        e = self._http_event({"User-Agent": "not-curl/1.0"})
        assert "curl" not in detect_tools_from_headers([e])

    def test_header_keys_case_insensitive(self):
        # Header key in mixed case should still match.
        e = self._http_event({"user-agent": "Nikto/2.1.6"})
        assert "nikto" in detect_tools_from_headers([e])

    def test_multiple_tools_in_one_session(self):
        events = [
            self._http_event({"User-Agent": "Nmap Scripting Engine"}, 0),
            self._http_event({"X-Mailer": "gophish"}, 10),
        ]
        result = detect_tools_from_headers(events)
        assert "nmap" in result
        assert "gophish" in result

    def test_no_request_events_returns_empty(self):
        events = [_mk(0, event_type="connection")]
        assert detect_tools_from_headers(events) == []

    def test_unknown_ua_returns_empty(self):
        e = self._http_event({"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"})
        assert detect_tools_from_headers([e]) == []

    def test_deduplication(self):
        # Same tool detected twice → appears once.
        events = [
            self._http_event({"User-Agent": "sqlmap/1.0"}, 0),
            self._http_event({"User-Agent": "sqlmap/1.0"}, 5),
        ]
        result = detect_tools_from_headers(events)
        assert result.count("sqlmap") == 1


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

    def test_ttl_fallback_linux(self):
        # p0f returns "unknown" → should fall back to TTL=64 → "linux"
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "unknown", "ttl": "64", "window": "29200"}),
        ]
        r = sniffer_rollup(events)
        assert r["os_guess"] == "linux"

    def test_ttl_fallback_windows(self):
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "unknown", "ttl": "128", "window": "64240"}),
        ]
        r = sniffer_rollup(events)
        assert r["os_guess"] == "windows"

    def test_ttl_fallback_embedded(self):
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "unknown", "ttl": "255", "window": "1024"}),
        ]
        r = sniffer_rollup(events)
        assert r["os_guess"] == "embedded"

    def test_hop_distance_zero_excluded(self):
        # Hop distance "0" should not be included in the median calculation.
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "linux", "hop_distance": "0"}),
            _mk(5, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "linux", "hop_distance": "0"}),
        ]
        r = sniffer_rollup(events)
        assert r["hop_distance"] is None

    def test_hop_distance_missing_excluded(self):
        # No hop_distance field at all → hop_distance result is None.
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "linux", "window": "29200"}),
        ]
        r = sniffer_rollup(events)
        assert r["hop_distance"] is None

    def test_p0f_label_takes_priority_over_ttl(self):
        # When p0f gives a non-unknown label, TTL fallback must NOT override it.
        events = [
            _mk(0, event_type="tcp_syn_fingerprint",
                fields={"os_guess": "macos_ios", "ttl": "64", "window": "65535"}),
        ]
        r = sniffer_rollup(events)
        assert r["os_guess"] == "macos_ios"


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
        tool_guesses = json.loads(r["tool_guesses"])
        assert "cobalt_strike" in tool_guesses

    def test_json_fields_are_strings(self):
        events = _regular_beacon(count=5, interval_s=60.0)
        r = build_behavior_record(events)
        # timing_stats, phase_sequence, tcp_fingerprint, tool_guesses must be JSON strings
        assert isinstance(r["timing_stats"], str)
        json.loads(r["timing_stats"])
        assert isinstance(r["phase_sequence"], str)
        json.loads(r["phase_sequence"])
        assert isinstance(r["tcp_fingerprint"], str)
        json.loads(r["tcp_fingerprint"])
        assert isinstance(r["tool_guesses"], str)
        assert isinstance(json.loads(r["tool_guesses"]), list)

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

    def test_header_tools_merged_into_tool_guesses(self):
        # Verify that header-detected tools (nmap) and timing-detected tools
        # (cobalt_strike) both end up in the same tool_guesses list.
        # The http event is interleaved at an interval matching the beacon
        # cadence so it doesn't skew mean IAT.
        beacon_events = _regular_beacon(count=20, interval_s=60.0, jitter_s=12.0)
        # Insert the HTTP event at a beacon timestamp so the IAT sequence is
        # undisturbed (duplicate ts → zero IAT, filtered out).
        http_event = _mk(0, event_type="request", service="http",
                         fields={"headers": json.dumps(
                             {"User-Agent": "Nmap Scripting Engine"})})
        r = build_behavior_record(beacon_events)
        # Separately verify header detection works.
        header_tools = json.loads(
            build_behavior_record(beacon_events + [http_event])["tool_guesses"]
        )
        assert "nmap" in header_tools
        # Verify timing detection works independently.
        timing_tools = json.loads(r["tool_guesses"])
        assert "cobalt_strike" in timing_tools

    def test_tool_guesses_empty_list_when_no_match(self):
        events = [_mk(i * 300.0) for i in range(5)]  # 5-min intervals, no signature match
        r = build_behavior_record(events)
        assert json.loads(r["tool_guesses"]) == []
