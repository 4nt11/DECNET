"""Per-rule unit tests for :class:`IntelLifter` (E.3.10).

Per Appendix A.10 each provider's mapping is exercised positively with
realistic payload shapes (categories, tags, ioc_type) and negatively
with null / missing signals. The lifter must NEVER import from
``decnet.intel.*``; the static guard at E.2.7 enforces that — these
tests are the behavioral counterpart.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.intel_lifter import IntelLifter
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.filesystem import _parse_and_compile
from tests.ttp._stub_store import StubRuleStore


_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "ttp"


def _compile(rule_id: str, state: RuleState | None = None) -> CompiledRule:
    return _parse_and_compile(
        _RULES_DIR / f"{rule_id}.yaml", state or RuleState(),
    )


def _ev(payload: dict[str, Any]) -> TaggerEvent:
    return TaggerEvent(
        source_kind="intel",
        source_id="src-intel",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload=payload,
    )


def _make_lifter(rule_ids: list[str]) -> IntelLifter:
    rules = [_compile(rid) for rid in rule_ids]
    lifter = IntelLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


# ── R0054 AbuseIPDB ────────────────────────────────────────────────


def test_abuseipdb_brute_force_category_emits_t1110() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 90,
        "abuseipdb_categories": [18, 22],
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1110" in techs


def test_abuseipdb_web_attack_emits_t1190() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [21],
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1190" in techs


def test_abuseipdb_email_spam_high_score_includes_t1566() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 90,  # gated >=80
        "abuseipdb_categories": [11],
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1566" in techs


def test_abuseipdb_email_spam_low_score_excludes_t1566() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 50,  # below the T1566 gate
        "abuseipdb_categories": [11],
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1566" not in techs


def test_abuseipdb_confidence_scaled_by_score() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 50,
        "abuseipdb_categories": [18],
    })))
    assert out
    # Base for T1110 in R0054 YAML is 0.7 → 0.7 * 0.5 = 0.35.
    for tag in out:
        if tag.technique_id == "T1110":
            assert tag.confidence == pytest.approx(0.35)


def test_abuseipdb_no_categories_no_emit() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({"abuseipdb_score": 95})))
    assert out == []


def test_abuseipdb_score_none_no_emit() -> None:
    lifter = _make_lifter(["R0054"])
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": None,
        "abuseipdb_categories": [18],
    })))
    assert out == []


# ── R0055 GreyNoise ────────────────────────────────────────────────


def test_greynoise_scanner_emits_t1595() -> None:
    lifter = _make_lifter(["R0055"])
    out = asyncio.run(lifter.tag(_ev({
        "greynoise_classification": "scanner",
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1595" in techs


def test_greynoise_c2_tag_emits_t1071() -> None:
    lifter = _make_lifter(["R0055"])
    out = asyncio.run(lifter.tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": ["cobalt_strike"],
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1071" in techs


def test_greynoise_benign_no_emit() -> None:
    lifter = _make_lifter(["R0055"])
    out = asyncio.run(lifter.tag(_ev({
        "greynoise_classification": "benign",
        "greynoise_tags": [],
    })))
    assert out == []


def test_greynoise_unknown_tag_no_emit() -> None:
    lifter = _make_lifter(["R0055"])
    out = asyncio.run(lifter.tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": ["random_unmapped"],
    })))
    assert out == []


# ── R0056 Feodo ────────────────────────────────────────────────────


def test_feodo_listed_emits_both() -> None:
    lifter = _make_lifter(["R0056"])
    out = asyncio.run(lifter.tag(_ev({
        "feodo_listed": True,
        "malware_family": "Emotet",
    })))
    techs = {tag.technique_id for tag in out}
    assert techs == {"T1071", "T1588"}
    for tag in out:
        assert tag.evidence.get("malware_family") == "Emotet"


def test_feodo_unlisted_no_emit() -> None:
    lifter = _make_lifter(["R0056"])
    out = asyncio.run(lifter.tag(_ev({"feodo_listed": False})))
    assert out == []


def test_feodo_missing_no_emit() -> None:
    lifter = _make_lifter(["R0056"])
    out = asyncio.run(lifter.tag(_ev({})))
    assert out == []


# ── R0057 ThreatFox ────────────────────────────────────────────────


def test_threatfox_botnet_cc_emits() -> None:
    lifter = _make_lifter(["R0057"])
    out = asyncio.run(lifter.tag(_ev({
        "ioc_type": "botnet_cc",
        "malware_family": "sliver",
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1071" in techs and "T1588" in techs
    for tag in out:
        assert tag.evidence.get("malware_family") == "sliver"


def test_threatfox_unknown_ioc_no_emit() -> None:
    lifter = _make_lifter(["R0057"])
    out = asyncio.run(lifter.tag(_ev({"ioc_type": "weird_unknown"})))
    assert out == []


# ── R0058 Aggregate bump (no-op in v0) ─────────────────────────────


def test_aggregate_bump_is_inert_in_v0() -> None:
    """R0058 is a bump-only meta-rule; the v0 lifter cannot bump
    cross-tag confidences from a single TaggerEvent. Stays no-op
    until E.3.14 worker bootstrap can plumb the cross-tag write."""
    lifter = _make_lifter(["R0058"])
    out = asyncio.run(lifter.tag(_ev({
        "aggregate_verdict": "malicious",
    })))
    assert out == []


# ── State modulation ───────────────────────────────────────────────


def test_disabled_intel_rule_no_emit() -> None:
    rule = _compile("R0054", RuleState(state="disabled"))
    lifter = IntelLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 95,
        "abuseipdb_categories": [18],
    })))
    assert out == []


def test_clipped_intel_rule_caps_confidence() -> None:
    rule = _compile("R0054", RuleState(state="clipped", confidence_max=0.5))
    lifter = IntelLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(_ev({
        "abuseipdb_score": 100,
        "abuseipdb_categories": [18],
    })))
    assert out
    for tag in out:
        # Base T1110 conf 0.7 × score 1.0 × ceiling 0.5 = 0.35
        assert tag.confidence <= 0.35 + 1e-6


# ── Decoupling guard (behavioral counterpart of E.2.7 static check) ─


def test_module_has_no_intel_imports() -> None:
    """IntelLifter must reach AttackerIntel data only via the upstream
    payload — never by importing from decnet.intel.*."""
    import decnet.ttp.impl.intel_lifter as mod  # noqa: PLC0415

    src = Path(mod.__file__ or "").read_text()
    assert "from decnet.intel" not in src
    assert "import decnet.intel" not in src


# ── Tolerance / no-error logging on absent payload ─────────────────


def test_empty_payload_returns_empty_no_errors(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    lifter = _make_lifter(["R0054", "R0055", "R0056", "R0057", "R0058"])
    out = asyncio.run(lifter.tag(_ev({})))
    assert out == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


# ── Ownership ──────────────────────────────────────────────────────


def test_owns_only_intel_prefix() -> None:
    behavioral = _compile("R0031")
    intel = _compile("R0054")
    lifter = IntelLifter(StubRuleStore(compiled=[behavioral, intel]))
    asyncio.run(lifter._index.hydrate_from(
        lifter._store, predicate=lifter._owns,  # type: ignore[arg-type]
    ))
    assert lifter._index.get("R0054") is not None
    assert lifter._index.get("R0031") is None
