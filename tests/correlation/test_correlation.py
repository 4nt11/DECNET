# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for the DECNET cross-decky correlation engine.

Covers:
- RFC 5424 line parsing (parser.py)
- Traversal graph data types (graph.py)
- CorrelationEngine ingestion, querying, and reporting (engine.py)
"""

from __future__ import annotations

import json
import re
from datetime import datetime


from decnet.correlation.parser import LogEvent, parse_line
from decnet.correlation.graph import AttackerTraversal, TraversalHop
from decnet.correlation.engine import CorrelationEngine, _fmt_duration
from decnet.logging.syslog_formatter import format_rfc5424, SEVERITY_INFO, SEVERITY_WARNING

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

_TS = "2026-04-04T10:00:00+00:00"
_TS2 = "2026-04-04T10:05:00+00:00"
_TS3 = "2026-04-04T10:10:00+00:00"


def _make_line(
    service: str = "http",
    hostname: str = "decky-01",
    event_type: str = "connection",
    src_ip: str = "1.2.3.4",
    timestamp: str = _TS,
    extra_fields: dict | None = None,
) -> str:
    """Build a real RFC 5424 DECNET syslog line via the formatter."""
    fields = {}
    if src_ip:
        fields["src_ip"] = src_ip
    if extra_fields:
        fields.update(extra_fields)
    return format_rfc5424(
        service=service,
        hostname=hostname,
        event_type=event_type,
        severity=SEVERITY_INFO,
        timestamp=datetime.fromisoformat(timestamp),
        **fields,
    )


def _make_line_src(hostname: str, src: str, timestamp: str = _TS) -> str:
    """Build a line that uses `src` instead of `src_ip` (mssql style)."""
    return format_rfc5424(
        service="mssql",
        hostname=hostname,
        event_type="unknown_packet",
        severity=SEVERITY_INFO,
        timestamp=datetime.fromisoformat(timestamp),
        src=src,
    )


# ---------------------------------------------------------------------------
# parser.py — parse_line
# ---------------------------------------------------------------------------

class TestParserBasic:
    def test_returns_none_for_blank(self):
        assert parse_line("") is None
        assert parse_line("   ") is None

    def test_returns_none_for_non_rfc5424(self):
        assert parse_line("this is not a syslog line") is None
        assert parse_line("Jan  1 00:00:00 host sshd: blah") is None

    def test_returns_log_event(self):
        event = parse_line(_make_line())
        assert isinstance(event, LogEvent)

    def test_hostname_extracted(self):
        event = parse_line(_make_line(hostname="decky-07"))
        assert event.decky == "decky-07"

    def test_service_extracted(self):
        event = parse_line(_make_line(service="ftp"))
        assert event.service == "ftp"

    def test_event_type_extracted(self):
        event = parse_line(_make_line(event_type="login_attempt"))
        assert event.event_type == "login_attempt"

    def test_timestamp_parsed(self):
        event = parse_line(_make_line(timestamp=_TS))
        assert event.timestamp == datetime.fromisoformat(_TS)

    def test_raw_line_preserved(self):
        line = _make_line()
        event = parse_line(line)
        assert event.raw == line.strip()


class TestParserBashPromptCommand:
    """
    Bash PROMPT_COMMAND lines from SSH/telnet decky containers arrive as
    free-form `logger -t bash "CMD …"` syslog with MSGID=NIL. The parser
    must rewrite them to event_type=command so the behavioral profiler
    picks them up.
    """

    _RAW = (
        '<14>1 2026-04-28T22:35:58.021674+00:00 dmz-gateway bash - - -  '
        'CMD uid=0 user=root src=31.56.209.39 pwd=/root '
        'cmd=echo "history -cw; rm -rf *.sh" | sh'
    )

    def test_event_type_normalized_to_command(self):
        event = parse_line(self._RAW)
        assert event is not None
        assert event.event_type == "command"

    def test_attacker_ip_extracted(self):
        event = parse_line(self._RAW)
        assert event.attacker_ip == "31.56.209.39"

    def test_command_field_captures_full_cmd_with_spaces(self):
        event = parse_line(self._RAW)
        assert event.fields["command"] == 'echo "history -cw; rm -rf *.sh" | sh'

    def test_metadata_fields_populated(self):
        event = parse_line(self._RAW)
        assert event.fields["uid"] == "0"
        assert event.fields["user"] == "root"
        assert event.fields["pwd"] == "/root"


class TestParserAttackerIP:
    def test_src_ip_field(self):
        event = parse_line(_make_line(src_ip="10.0.0.1"))
        assert event.attacker_ip == "10.0.0.1"

    def test_src_field_fallback(self):
        """mssql logs use `src` instead of `src_ip`."""
        event = parse_line(_make_line_src("decky-win", "192.168.1.5"))
        assert event.attacker_ip == "192.168.1.5"

    def test_no_ip_field_gives_none(self):
        line = format_rfc5424("http", "decky-01", "startup", SEVERITY_INFO)
        event = parse_line(line)
        assert event is not None
        assert event.attacker_ip is None

    def test_extra_fields_in_dict(self):
        event = parse_line(_make_line(extra_fields={"username": "root", "password": "admin"}))
        assert event.fields["username"] == "root"
        assert event.fields["password"] == "admin"

    def test_src_ip_priority_over_src(self):
        """src_ip should win when both are present."""
        line = format_rfc5424(
            "mssql", "decky-01", "evt", SEVERITY_INFO,
            timestamp=datetime.fromisoformat(_TS),
            src_ip="1.1.1.1",
            src="2.2.2.2",
        )
        event = parse_line(line)
        assert event.attacker_ip == "1.1.1.1"

    def test_sd_escape_chars_decoded(self):
        """Escaped characters in SD values should be unescaped."""
        line = format_rfc5424(
            "http", "decky-01", "evt", SEVERITY_INFO,
            timestamp=datetime.fromisoformat(_TS),
            src_ip="1.2.3.4",
            path='/search?q=a"b',
        )
        event = parse_line(line)
        assert '"' in event.fields["path"]

    def test_nilvalue_hostname_skipped(self):
        line = format_rfc5424("-", "decky-01", "evt", SEVERITY_INFO)
        assert parse_line(line) is None

    def test_nilvalue_service_skipped(self):
        line = format_rfc5424("http", "-", "evt", SEVERITY_INFO)
        assert parse_line(line) is None

    def test_attacker_ip_from_sshd_prose(self):
        """sshd routed via rsyslog has no SD block — IP lives in free prose.
        Anchored "from <ip>" must beat the local listener in
        "Connection from X port Y on Z port 22"."""
        cases = [
            (
                "<38>1 2026-04-27T03:08:48+00:00 dmz-gateway sshd - - - "
                "Failed password for root from 157.66.144.16 port 42772 ssh2",
                "157.66.144.16",
            ),
            (
                "<38>1 2026-04-27T03:08:45+00:00 dmz-gateway sshd - - - "
                "Connection from 157.66.144.16 port 42772 on 10.0.0.2 port 22",
                "157.66.144.16",
            ),
            (
                "<38>1 2026-04-27T03:08:46+00:00 dmz-gateway sshd - - - "
                "pam_unix(sshd:auth): authentication failure; rhost=157.66.144.16 user=root",
                "157.66.144.16",
            ),
        ]
        for line, expected in cases:
            event = parse_line(line)
            assert event is not None, line
            assert event.attacker_ip == expected, (line, event.attacker_ip)


# ---------------------------------------------------------------------------
# graph.py — AttackerTraversal
# ---------------------------------------------------------------------------

def _make_traversal(ip: str, hops_spec: list[tuple]) -> AttackerTraversal:
    """hops_spec: list of (ts_str, decky, service, event_type)"""
    hops = [
        TraversalHop(
            timestamp=datetime.fromisoformat(ts),
            decky=decky,
            service=svc,
            event_type=evt,
        )
        for ts, decky, svc, evt in hops_spec
    ]
    return AttackerTraversal(attacker_ip=ip, hops=hops)


class TestTraversalGraph:
    def setup_method(self):
        self.t = _make_traversal("5.6.7.8", [
            (_TS,  "decky-01", "ssh",  "login_attempt"),
            (_TS2, "decky-03", "http", "request"),
            (_TS3, "decky-05", "ftp",  "auth_attempt"),
        ])

    def test_first_seen(self):
        assert self.t.first_seen == datetime.fromisoformat(_TS)

    def test_last_seen(self):
        assert self.t.last_seen == datetime.fromisoformat(_TS3)

    def test_duration_seconds(self):
        assert self.t.duration_seconds == 600.0

    def test_deckies_ordered(self):
        assert self.t.deckies == ["decky-01", "decky-03", "decky-05"]

    def test_decky_count(self):
        assert self.t.decky_count == 3

    def test_path_string(self):
        assert self.t.path == "decky-01 → decky-03 → decky-05"

    def test_to_dict_keys(self):
        d = self.t.to_dict()
        assert d["attacker_ip"] == "5.6.7.8"
        assert d["decky_count"] == 3
        assert d["hop_count"] == 3
        assert len(d["hops"]) == 3
        assert d["path"] == "decky-01 → decky-03 → decky-05"

    def test_to_dict_hops_structure(self):
        hop = self.t.to_dict()["hops"][0]
        assert set(hop.keys()) == {"timestamp", "decky", "service", "event_type"}

    def test_repeated_decky_not_double_counted_in_path(self):
        t = _make_traversal("1.1.1.1", [
            (_TS,  "decky-01", "ssh", "conn"),
            (_TS2, "decky-02", "ftp", "conn"),
            (_TS3, "decky-01", "ssh", "conn"),  # revisit
        ])
        assert t.deckies == ["decky-01", "decky-02"]
        assert t.decky_count == 2


# ---------------------------------------------------------------------------
# engine.py — CorrelationEngine
# ---------------------------------------------------------------------------

class TestEngineIngestion:
    def test_ingest_returns_event(self):
        engine = CorrelationEngine()
        evt = engine.ingest(_make_line())
        assert evt is not None

    def test_ingest_blank_returns_none(self):
        engine = CorrelationEngine()
        assert engine.ingest("") is None

    def test_lines_parsed_counter(self):
        engine = CorrelationEngine()
        engine.ingest(_make_line())
        engine.ingest("garbage")
        assert engine.lines_parsed == 2

    def test_events_indexed_counter(self):
        engine = CorrelationEngine()
        engine.ingest(_make_line(src_ip="1.2.3.4"))
        engine.ingest(_make_line(src_ip=""))      # no IP
        assert engine.events_indexed == 1

    def test_ingest_file(self, tmp_path):
        log = tmp_path / "decnet.log"
        lines = [
            _make_line("ssh",  "decky-01", "conn",  "10.0.0.1", _TS),
            _make_line("http", "decky-02", "req",   "10.0.0.1", _TS2),
            _make_line("ftp",  "decky-03", "auth",  "10.0.0.1", _TS3),
        ]
        log.write_text("\n".join(lines))
        engine = CorrelationEngine()
        count = engine.ingest_file(log)
        assert count == 3


class TestEngineTraversals:
    def _engine_with(self, specs: list[tuple]) -> CorrelationEngine:
        """specs: (service, decky, event_type, src_ip, timestamp)"""
        engine = CorrelationEngine()
        for svc, decky, evt, ip, ts in specs:
            engine.ingest(_make_line(svc, decky, evt, ip, ts))
        return engine

    def test_single_decky_not_a_traversal(self):
        engine = self._engine_with([
            ("ssh", "decky-01", "conn", "1.1.1.1", _TS),
            ("ssh", "decky-01", "conn", "1.1.1.1", _TS2),
        ])
        assert engine.traversals() == []

    def test_two_deckies_is_traversal(self):
        engine = self._engine_with([
            ("ssh",  "decky-01", "conn", "1.1.1.1", _TS),
            ("http", "decky-02", "req",  "1.1.1.1", _TS2),
        ])
        t = engine.traversals()
        assert len(t) == 1
        assert t[0].attacker_ip == "1.1.1.1"
        assert t[0].decky_count == 2

    def test_prober_event_does_not_count_as_traversal(self):
        """Hit live on first VPS deploy: every fingerprinted attacker
        showed up as a 2-decky traversal because the prober's outbound
        fingerprint events (decky=decnet-prober, target_ip=<attacker>)
        got co-indexed with the attacker's actual decoy hops. The
        prober is internal infrastructure, not a hop — its events
        must not bump the distinct-decky count."""
        engine = self._engine_with([
            ("ssh", "dmz-gateway", "conn", "1.1.1.1", _TS),
            ("ssh", "decnet-prober", "hassh_fingerprint", "1.1.1.1", _TS2),
        ])
        # Only one *real* decky touched — no traversal.
        assert engine.traversals() == []

    def test_prober_excluded_from_traversal_path(self):
        """When a real traversal exists, the prober's hops must not
        appear in the path or inflate the decky count."""
        engine = self._engine_with([
            ("ssh",  "dmz-gateway",   "conn",              "1.1.1.1", _TS),
            ("ssh",  "decnet-prober", "hassh_fingerprint", "1.1.1.1", _TS2),
            ("http", "decky-internal", "req",              "1.1.1.1", _TS3),
        ])
        traversals = engine.traversals()
        assert len(traversals) == 1
        t = traversals[0]
        assert t.decky_count == 2, (
            f"prober should not inflate decky_count; got {t.decky_count}"
        )
        assert "decnet-prober" not in t.path, (
            f"prober should not appear in traversal path; got {t.path!r}"
        )

    def test_min_deckies_filter(self):
        engine = self._engine_with([
            ("ssh",  "decky-01", "conn", "1.1.1.1", _TS),
            ("http", "decky-02", "req",  "1.1.1.1", _TS2),
            ("ftp",  "decky-03", "auth", "1.1.1.1", _TS3),
        ])
        assert len(engine.traversals(min_deckies=3)) == 1
        assert len(engine.traversals(min_deckies=4)) == 0

    def test_multiple_attackers_separate_traversals(self):
        engine = self._engine_with([
            ("ssh",  "decky-01", "conn", "1.1.1.1", _TS),
            ("http", "decky-02", "req",  "1.1.1.1", _TS2),
            ("ssh",  "decky-03", "conn", "9.9.9.9", _TS),
            ("ftp",  "decky-04", "auth", "9.9.9.9", _TS2),
        ])
        traversals = engine.traversals()
        assert len(traversals) == 2
        ips = {t.attacker_ip for t in traversals}
        assert ips == {"1.1.1.1", "9.9.9.9"}

    def test_traversals_sorted_by_first_seen(self):
        engine = self._engine_with([
            ("ssh",  "decky-01", "conn", "9.9.9.9", _TS2),   # later
            ("ftp",  "decky-02", "auth", "9.9.9.9", _TS3),
            ("http", "decky-03", "req",  "1.1.1.1", _TS),    # earlier
            ("smb",  "decky-04", "auth", "1.1.1.1", _TS2),
        ])
        traversals = engine.traversals()
        assert traversals[0].attacker_ip == "1.1.1.1"
        assert traversals[1].attacker_ip == "9.9.9.9"

    def test_hops_ordered_chronologically(self):
        engine = self._engine_with([
            ("ftp",  "decky-02", "auth", "5.5.5.5", _TS2),  # ingested first but later ts
            ("ssh",  "decky-01", "conn", "5.5.5.5", _TS),
        ])
        t = engine.traversals()[0]
        assert t.hops[0].decky == "decky-01"
        assert t.hops[1].decky == "decky-02"

    def test_all_attackers(self):
        engine = self._engine_with([
            ("ssh", "decky-01", "conn", "1.1.1.1", _TS),
            ("ssh", "decky-01", "conn", "1.1.1.1", _TS2),
            ("ssh", "decky-01", "conn", "2.2.2.2", _TS),
        ])
        attackers = engine.all_attackers()
        assert attackers["1.1.1.1"] == 2
        assert attackers["2.2.2.2"] == 1

    def test_mssql_src_field_correlated(self):
        """Verify that `src=` (mssql style) is picked up for cross-decky correlation."""
        engine = CorrelationEngine()
        engine.ingest(_make_line_src("decky-win1", "10.10.10.5", _TS))
        engine.ingest(_make_line_src("decky-win2", "10.10.10.5", _TS2))
        t = engine.traversals()
        assert len(t) == 1
        assert t[0].decky_count == 2


class TestEngineReporting:
    def _two_decky_engine(self) -> CorrelationEngine:
        engine = CorrelationEngine()
        engine.ingest(_make_line("ssh",  "decky-01", "conn", "3.3.3.3", _TS))
        engine.ingest(_make_line("http", "decky-02", "req",  "3.3.3.3", _TS2))
        return engine

    def test_report_json_structure(self):
        engine = self._two_decky_engine()
        report = engine.report_json()
        assert "stats" in report
        assert "traversals" in report
        assert report["stats"]["traversals"] == 1
        t = report["traversals"][0]
        assert t["attacker_ip"] == "3.3.3.3"
        assert t["decky_count"] == 2

    def test_report_json_serialisable(self):
        engine = self._two_decky_engine()
        # Should not raise
        json.dumps(engine.report_json())

    def test_report_table_returns_rich_table(self):
        from rich.table import Table
        engine = self._two_decky_engine()
        table = engine.report_table()
        assert isinstance(table, Table)

    def test_traversal_syslog_lines_count(self):
        engine = self._two_decky_engine()
        lines = engine.traversal_syslog_lines()
        assert len(lines) == 1

    def test_traversal_syslog_line_is_rfc5424(self):
        engine = self._two_decky_engine()
        line = engine.traversal_syslog_lines()[0]
        # Must match RFC 5424 header
        assert re.match(r"^<\d+>1 \S+ \S+ correlator - traversal_detected", line)

    def test_traversal_syslog_contains_attacker_ip(self):
        engine = self._two_decky_engine()
        line = engine.traversal_syslog_lines()[0]
        assert "3.3.3.3" in line

    def test_traversal_syslog_severity_is_warning(self):
        engine = self._two_decky_engine()
        line = engine.traversal_syslog_lines()[0]
        pri = int(re.match(r"^<(\d+)>", line).group(1))
        assert pri == 16 * 8 + SEVERITY_WARNING  # local0 + warning

    def test_no_traversals_empty_json(self):
        engine = CorrelationEngine()
        engine.ingest(_make_line())  # single decky, no traversal
        assert engine.report_json()["stats"]["traversals"] == 0
        assert engine.traversal_syslog_lines() == []


# ---------------------------------------------------------------------------
# _fmt_duration helper
# ---------------------------------------------------------------------------

class TestFmtDuration:
    def test_seconds(self):
        assert _fmt_duration(45) == "45s"

    def test_minutes(self):
        assert _fmt_duration(90) == "1.5m"

    def test_hours(self):
        assert _fmt_duration(7200) == "2.0h"


# ---------------------------------------------------------------------------
# Mutation-event stream (parser kind + engine index + graph markers)
# ---------------------------------------------------------------------------

def _mutation_line(
    decky: str,
    *,
    old: str = "",
    new: str = "ssh",
    trigger: str = "scheduled",
    timestamp: str = _TS,
) -> str:
    return format_rfc5424(
        service="mutator",
        hostname=decky,
        event_type="decky_mutated",
        severity=SEVERITY_INFO,
        timestamp=datetime.fromisoformat(timestamp),
        decky=decky,
        old_services=old,
        new_services=new,
        trigger=trigger,
    )


class TestParserMutationKind:
    def test_mutator_line_kind_is_mutation(self):
        ev = parse_line(_mutation_line("decky-01", old="ssh", new="rdp",
                                       trigger="scheduled"))
        assert ev is not None
        assert ev.kind == "mutation"

    def test_default_kind_is_attacker(self):
        ev = parse_line(_make_line())
        assert ev is not None
        assert ev.kind == "attacker"

    def test_non_mutator_service_stays_attacker(self):
        # Same event_type but different service ⇒ not a mutation
        line = format_rfc5424(
            service="ssh",
            hostname="decky-01",
            event_type="decky_mutated",
            severity=SEVERITY_INFO,
            timestamp=datetime.fromisoformat(_TS),
            src_ip="1.1.1.1",
        )
        ev = parse_line(line)
        assert ev is not None
        assert ev.kind == "attacker"


class TestEngineMutationIndex:
    def test_mutation_indexed_separately(self):
        engine = CorrelationEngine()
        engine.ingest(_mutation_line("decky-01", old="ssh", new="rdp"))
        assert engine.mutations_indexed == 1
        assert engine.events_indexed == 0
        assert "decky-01" in engine._mutations
        assert "decky-01" not in engine._events

    def test_mutations_interleaved_into_traversal(self):
        engine = CorrelationEngine()
        # Attacker hits decky-01 and decky-02; decky-01 mutates in between
        engine.ingest(_make_line(hostname="decky-01", src_ip="9.9.9.9",
                                 timestamp=_TS))
        engine.ingest(_mutation_line("decky-01", old="ssh", new="rdp",
                                     trigger="scheduled", timestamp=_TS2))
        engine.ingest(_make_line(hostname="decky-02", src_ip="9.9.9.9",
                                 timestamp=_TS3))
        traversals = engine.traversals()
        assert len(traversals) == 1
        t = traversals[0]
        assert len(t.mutations_during) == 1
        m = t.mutations_during[0]
        assert m.decky == "decky-01"
        assert m.old_services == ["ssh"]
        assert m.new_services == ["rdp"]
        assert m.trigger == "scheduled"

    def test_mutation_outside_window_excluded(self):
        engine = CorrelationEngine()
        # Mutation at _TS — before attacker first_seen at _TS2
        engine.ingest(_mutation_line("decky-01", old="", new="ssh",
                                     trigger="creation", timestamp=_TS))
        engine.ingest(_make_line(hostname="decky-01", src_ip="9.9.9.9",
                                 timestamp=_TS2))
        engine.ingest(_make_line(hostname="decky-02", src_ip="9.9.9.9",
                                 timestamp=_TS3))
        t = engine.traversals()[0]
        # The creation happened BEFORE first contact, so it's not "during"
        assert t.mutations_during == []

    def test_mutation_on_untouched_decky_excluded(self):
        engine = CorrelationEngine()
        engine.ingest(_make_line(hostname="decky-01", src_ip="9.9.9.9",
                                 timestamp=_TS))
        engine.ingest(_make_line(hostname="decky-02", src_ip="9.9.9.9",
                                 timestamp=_TS3))
        # decky-03 mutates mid-window but the attacker never touched it
        engine.ingest(_mutation_line("decky-03", old="ftp", new="smtp",
                                     trigger="operator", timestamp=_TS2))
        t = engine.traversals()[0]
        assert t.mutations_during == []

    def test_to_dict_includes_timeline_with_markers(self):
        engine = CorrelationEngine()
        engine.ingest(_make_line(hostname="decky-01", src_ip="9.9.9.9",
                                 timestamp=_TS))
        engine.ingest(_mutation_line("decky-01", old="ssh", new="rdp",
                                     trigger="scheduled", timestamp=_TS2))
        engine.ingest(_make_line(hostname="decky-02", src_ip="9.9.9.9",
                                 timestamp=_TS3))
        d = engine.traversals()[0].to_dict()
        assert len(d["mutations_during"]) == 1
        assert d["mutations_during"][0]["trigger"] == "scheduled"
        kinds = [entry["kind"] for entry in d["timeline"]]
        assert kinds == ["hop", "mutation", "hop"]

    def test_report_json_serialisable_with_mutations(self):
        engine = CorrelationEngine()
        engine.ingest(_make_line(hostname="decky-01", src_ip="9.9.9.9",
                                 timestamp=_TS))
        engine.ingest(_mutation_line("decky-01", old="ssh", new="rdp",
                                     trigger="scheduled", timestamp=_TS2))
        engine.ingest(_make_line(hostname="decky-02", src_ip="9.9.9.9",
                                 timestamp=_TS3))
        json.dumps(engine.report_json())  # must not raise
