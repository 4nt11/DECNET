"""Per-rule unit tests for :class:`BehavioralLifter` (E.3.9).

Each R003N gets a positive payload that fires the predicate and a
negative payload that does not. State modulation is tested once
(disable / clip) since it's funneled through the shared
:func:`is_active` / :func:`apply_ceiling` helpers.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.behavioral_lifter import BehavioralLifter
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.filesystem import _parse_and_compile
from tests.ttp._stub_store import StubRuleStore


_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "ttp"


def _compile(rule_id: str, state: RuleState | None = None) -> CompiledRule:
    return _parse_and_compile(
        _RULES_DIR / f"{rule_id}.yaml", state or RuleState(),
    )


def _ev(source_kind: str, payload: dict[str, Any]) -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id=f"src-{source_kind}",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id="sess1",
        decky_id=None,
        payload=payload,
    )


def _make_lifter_with(rule_ids: list[str]) -> BehavioralLifter:
    rules = [_compile(rid) for rid in rule_ids]
    lifter = BehavioralLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


# ── Per-rule positive cases ─────────────────────────────────────────


@pytest.mark.parametrize(
    "rule_id,source_kind,payload,techniques",
    [
        (
            "R0031",
            "session",
            {"beacon_interval_s": 60, "beacon_jitter_pct": 0.05},
            {"T1071", "T1029"},
        ),
        (
            "R0032",
            "session",
            {"command_text": "FLUSHALL", "op_text": "FLUSHALL"},
            {"T1485"},
        ),
        (
            "R0033",
            "session",
            {"body_text": "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to decrypt"},
            {"T1486"},
        ),
        (
            "R0034",
            "session",
            {"bytes_out": 5_000_000, "request_count": 100},
            {"T1567"},
        ),
        (
            "R0035",
            "session",
            {"rows_read": 50_000, "bytes_read": 1_000},
            {"T1213"},
        ),
        (
            "R0036",
            "http_request",
            {"request_path": "/var/www/.env"},
            {"T1552"},
        ),
        (
            "R0037",
            "http_request",
            {"request_path": "/api/v1/namespaces/default/secrets"},
            {"T1552"},
        ),
        (
            "R0038",
            "session",
            {"signals": ["privileged:true", "image:nginx"]},
            {"T1611"},
        ),
        (
            "R0039",
            "session",
            {"llmnr_poisoned": True},
            {"T1557"},
        ),
        (
            "R0040",
            "session",
            {"tftp_filename": "router-startup-config"},
            {"T1602"},
        ),
    ],
)
def test_rule_fires_on_positive_payload(
    rule_id: str,
    source_kind: str,
    payload: dict[str, Any],
    techniques: set[str],
) -> None:
    lifter = _make_lifter_with([rule_id])
    out = asyncio.run(lifter.tag(_ev(source_kind, payload)))
    assert out, f"{rule_id} did not fire on its positive payload"
    fired = {tag.technique_id for tag in out}
    assert fired == techniques
    for tag in out:
        assert tag.rule_id == rule_id
        assert tag.attacker_uuid == "att1"


# ── Negative cases ──────────────────────────────────────────────────


def test_beaconing_rejects_high_jitter() -> None:
    lifter = _make_lifter_with(["R0031"])
    out = asyncio.run(lifter.tag(
        _ev("session", {"beacon_interval_s": 60, "beacon_jitter_pct": 0.5}),
    ))
    assert out == []


def test_beaconing_rejects_short_interval() -> None:
    lifter = _make_lifter_with(["R0031"])
    out = asyncio.run(lifter.tag(
        _ev("session", {"beacon_interval_s": 2, "beacon_jitter_pct": 0.05}),
    ))
    assert out == []


def test_data_destruction_rejects_unrelated_text() -> None:
    lifter = _make_lifter_with(["R0032"])
    out = asyncio.run(lifter.tag(
        _ev("session", {"command_text": "SELECT 1"}),
    ))
    assert out == []


def test_ransom_note_requires_btc_or_xmr_when_flagged() -> None:
    lifter = _make_lifter_with(["R0033"])
    # has keyword but no address
    out = asyncio.run(lifter.tag(
        _ev("session", {"body_text": "send bitcoin to decrypt"}),
    ))
    assert out == []


def test_exfil_below_thresholds_no_fire() -> None:
    lifter = _make_lifter_with(["R0034"])
    out = asyncio.run(lifter.tag(
        _ev("session", {"bytes_out": 100, "request_count": 1}),
    ))
    assert out == []


def test_path_match_rules_skip_unrelated_paths() -> None:
    lifter = _make_lifter_with(["R0036", "R0037"])
    out = asyncio.run(lifter.tag(
        _ev("http_request", {"request_path": "/index.html"}),
    ))
    assert out == []


def test_event_source_kind_outside_applies_to_no_fire() -> None:
    """A behavioral rule with applies_to=[session] must not fire on
    an http_request event even if the predicate would otherwise pass.
    """
    lifter = _make_lifter_with(["R0031"])
    out = asyncio.run(lifter.tag(
        _ev("http_request", {"beacon_interval_s": 60, "beacon_jitter_pct": 0.05}),
    ))
    assert out == []


# ── State modulation ────────────────────────────────────────────────


def test_disabled_state_skips_emit() -> None:
    rule = _compile("R0031", RuleState(state="disabled"))
    lifter = BehavioralLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(
        _ev("session", {"beacon_interval_s": 60, "beacon_jitter_pct": 0.05}),
    ))
    assert out == []


def test_clipped_state_caps_confidence() -> None:
    rule = _compile("R0031", RuleState(state="clipped", confidence_max=0.5))
    lifter = BehavioralLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(
        _ev("session", {"beacon_interval_s": 60, "beacon_jitter_pct": 0.05}),
    ))
    # Base confidences in YAML are 0.8 and 0.85; clipped to 0.5 ceiling
    # → 0.4 and 0.425 respectively.
    assert out
    for tag in out:
        assert tag.confidence < 0.5


def test_expired_state_treated_as_disabled() -> None:
    rule = _compile(
        "R0031",
        RuleState(
            state="enabled",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        ),
    )
    lifter = BehavioralLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(
        _ev("session", {"beacon_interval_s": 60, "beacon_jitter_pct": 0.05}),
    ))
    assert out == []


# ── Ownership / hot-reload via watch_store hydration ────────────────


def test_owns_only_behavioral_prefix() -> None:
    intel = _compile("R0054")  # match.kind = lifter:intel_abuseipdb
    behavioral = _compile("R0031")
    lifter = BehavioralLifter(
        StubRuleStore(compiled=[intel, behavioral]),
    )
    asyncio.run(lifter._index.hydrate_from(
        lifter._store, predicate=lifter._owns,  # type: ignore[arg-type]
    ))
    assert lifter._index.get("R0031") is not None
    assert lifter._index.get("R0054") is None


def test_tolerates_absent_payload(caplog: pytest.LogCaptureFixture) -> None:
    """The empty payload steady-state must not produce ERROR records."""
    caplog.set_level(logging.DEBUG)
    lifter = _make_lifter_with(["R0031", "R0032", "R0036"])
    out = asyncio.run(lifter.tag(_ev("session", {})))
    assert out == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
