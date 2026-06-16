# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-predicate unit tests for :class:`HttpFingerprintLifter` (PR2).

Covers HFP-0001 (scanner JA4H), HFP-0002 (h2/h3 settings probe),
and HFP-0003 (QUIC probe) using synthetic CompiledRule stubs injected
directly into the lifter's RuleIndex — no YAML on disk required.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.http_fingerprint_lifter import HttpFingerprintLifter
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState
from tests.ttp._stub_store import StubRuleStore


_EMITS_BY_RULE: dict[str, tuple] = {
    "HFP-0001": (("T1592", "002", "TA0043", 0.6),),
    "HFP-0002": (("T1046", None, "TA0043", 0.6),),
    "HFP-0003": (("T1046", None, "TA0043", 0.6),),
}


def _rule(rule_id: str, applies_to: str = "http_fingerprint") -> CompiledRule:
    return CompiledRule(
        rule_id=rule_id,
        rule_version=1,
        name=rule_id,
        applies_to=frozenset({applies_to}),
        match_spec={},
        emits=_EMITS_BY_RULE.get(rule_id, ()),
        evidence_fields=(),
        state=RuleState(),
    )


def _make_lifter(*rule_ids: str) -> HttpFingerprintLifter:
    rules = [_rule(rid) for rid in rule_ids]
    lifter = HttpFingerprintLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


def _ev(payload: dict[str, Any]) -> TaggerEvent:
    return TaggerEvent(
        source_kind="http_fingerprint",
        source_id="src-fp",
        attacker_uuid="att-1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload=payload,
    )


# ── HFP-0001: scanner JA4H prefix match ─────────────────────────────


class TestScannerJA4H:
    def test_curl_h1_ja4h_fires(self):
        lifter = _make_lifter("HFP-0001")
        out = asyncio.run(lifter.tag(_ev({
            "ja4h": "GE11nn0000_02_abc123def456_000000000000",
            "protocol": "h1",
            "client_ip": "1.2.3.4",
            "seen_at": "2026-05-10T00:00:00Z",
        })))
        assert out, "HFP-0001 must fire on curl-default JA4H prefix"
        assert out[0].technique_id == "T1592"

    def test_curl_h2_ja4h_fires(self):
        lifter = _make_lifter("HFP-0001")
        out = asyncio.run(lifter.tag(_ev({
            "ja4h": "GE20nn0000_02_abc123def456_000000000000",
            "protocol": "h2",
        })))
        assert out

    def test_browser_ja4h_no_fire(self):
        lifter = _make_lifter("HFP-0001")
        out = asyncio.run(lifter.tag(_ev({
            "ja4h": "GE11cn0000_08_realbrwsr1234_000000000000",
            "protocol": "h1",
        })))
        assert out == []

    def test_missing_ja4h_no_fire(self):
        lifter = _make_lifter("HFP-0001")
        out = asyncio.run(lifter.tag(_ev({"protocol": "h1"})))
        assert out == []

    def test_evidence_keys_match_typeddict(self):
        lifter = _make_lifter("HFP-0001")
        out = asyncio.run(lifter.tag(_ev({
            "ja4h": "GE11nn0000_02_abc123def456_000000000000",
            "protocol": "h1",
            "client_ip": "10.0.0.1",
            "seen_at": "2026-05-10T00:00:00Z",
        })))
        assert out
        ev = out[0].evidence
        assert set(ev) == {"kind", "hash", "protocol", "client_ip", "seen_at", "raw"}
        assert ev["kind"] == "ja4h"
        assert ev["protocol"] == "h1"

    def test_rule_not_installed_no_fire(self):
        lifter = _make_lifter()  # no rules installed
        out = asyncio.run(lifter.tag(_ev({
            "ja4h": "GE11nn0000_02_abc_000000000000",
        })))
        assert out == []


# ── HFP-0002: h2/h3 settings probe ──────────────────────────────────


class TestH2H3Probe:
    def test_h2_settings_fires(self):
        lifter = _make_lifter("HFP-0002")
        out = asyncio.run(lifter.tag(_ev({
            "fingerprint_type": "http2_settings",
            "settings": {"HEADER_TABLE_SIZE": 65536},
            "client_ip": "5.6.7.8",
            "seen_at": "2026-05-10T00:00:00Z",
        })))
        assert out, "HFP-0002 must fire on http2_settings"
        assert out[0].technique_id == "T1046"

    def test_h3_settings_fires(self):
        lifter = _make_lifter("HFP-0002")
        out = asyncio.run(lifter.tag(_ev({
            "fingerprint_type": "http3_settings",
            "settings": {"QPACK_MAX_TABLE_CAPACITY": 0},
        })))
        assert out
        ev = out[0].evidence
        assert ev["protocol"] == "h3"

    def test_h2_settings_evidence_carries_raw(self):
        lifter = _make_lifter("HFP-0002")
        settings = {"HEADER_TABLE_SIZE": 4096, "MAX_CONCURRENT_STREAMS": 100}
        out = asyncio.run(lifter.tag(_ev({
            "fingerprint_type": "http2_settings",
            "settings": settings,
        })))
        assert out
        assert out[0].evidence["raw"] == settings

    def test_ja4h_event_does_not_fire_h2_probe(self):
        lifter = _make_lifter("HFP-0002")
        out = asyncio.run(lifter.tag(_ev({
            "ja4h": "GE11nn0000_02_abc_000000000000",
        })))
        assert out == []

    def test_unknown_fp_type_no_fire(self):
        lifter = _make_lifter("HFP-0002")
        out = asyncio.run(lifter.tag(_ev({
            "fingerprint_type": "ja3",
        })))
        assert out == []


# ── HFP-0003: QUIC probe ─────────────────────────────────────────────


class TestQuicProbe:
    def test_ja4_quic_fires(self):
        lifter = _make_lifter("HFP-0003")
        out = asyncio.run(lifter.tag(_ev({
            "ja4_quic": "q13d0310h2_002f,0035_0403,0804_h3",
            "client_ip": "9.8.7.6",
            "seen_at": "2026-05-10T00:00:00Z",
        })))
        assert out, "HFP-0003 must fire on ja4_quic"
        assert out[0].technique_id == "T1046"

    def test_evidence_protocol_is_h3(self):
        lifter = _make_lifter("HFP-0003")
        out = asyncio.run(lifter.tag(_ev({
            "ja4_quic": "q13d0310h2_002f,0035_0403,0804_h3",
        })))
        assert out
        assert out[0].evidence["protocol"] == "h3"
        assert out[0].evidence["kind"] == "ja4_quic"

    def test_missing_ja4_quic_no_fire(self):
        lifter = _make_lifter("HFP-0003")
        out = asyncio.run(lifter.tag(_ev({"client_ip": "1.1.1.1"})))
        assert out == []


# ── Combined: all three rules installed ──────────────────────────────


class TestAllRulesCombined:
    def test_only_matching_rule_fires(self):
        lifter = _make_lifter("HFP-0001", "HFP-0002", "HFP-0003")
        # h2_settings payload should only fire HFP-0002
        out = asyncio.run(lifter.tag(_ev({
            "fingerprint_type": "http2_settings",
            "settings": {},
        })))
        rule_ids = {tag.rule_id for tag in out}
        assert "HFP-0002" in rule_ids
        assert "HFP-0001" not in rule_ids
        assert "HFP-0003" not in rule_ids

    def test_empty_payload_no_errors(self):
        lifter = _make_lifter("HFP-0001", "HFP-0002", "HFP-0003")
        out = asyncio.run(lifter.tag(_ev({})))
        assert out == []

    def test_handles_only_http_fingerprint(self):
        assert HttpFingerprintLifter.HANDLES == frozenset({"http_fingerprint"})
