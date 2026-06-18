# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-rule unit tests for :class:`IntelLifter` (E.3.10 + 2026-05-02 audit).

Per Appendix A.10 each provider's mapping is exercised positively with
realistic payload shapes (categories, tags, threat_types) and negatively
with null / missing signals. The lifter must NEVER import from
``decnet.intel.*``; the static guard at E.2.7 enforces that — these
tests are the behavioral counterpart.

The 2026-05-02 ship-time audit found a class of cascade bugs where
``_emit_filtered`` silently dropped predicate decisions whose
``technique_id`` was missing from the rule YAML's ``emits`` list. The
test suite below exercises every previously-dropped technique end-to-
end so a regression of the same kind shows up immediately.
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


def _techs(out: list[Any]) -> set[str]:
    return {tag.technique_id for tag in out}


# ── R0054 AbuseIPDB — corrected v2 mapping ────────────────────────────


def test_abuseipdb_brute_force_category_emits_t1110() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 90,
        "abuseipdb_categories": [18, 22],
    })))
    assert "T1110" in _techs(out)


def test_abuseipdb_web_attack_emits_t1190() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [21],
    })))
    assert "T1190" in _techs(out)


def test_abuseipdb_email_spam_high_score_includes_t1566_and_t1496() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 90,
        "abuseipdb_categories": [11],
    })))
    techs = _techs(out)
    assert {"T1566", "T1496"} <= techs


def test_abuseipdb_email_spam_low_score_excludes_t1566() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 50,
        "abuseipdb_categories": [11],
    })))
    techs = _techs(out)
    assert "T1566" not in techs
    assert "T1496" in techs  # ungated, still fires


def test_abuseipdb_port_scan_emits_t1046_and_t1595() -> None:
    """Cat 14 → T1046 + T1595. Both were silently dropped pre-v2."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [14],
    })))
    assert {"T1046", "T1595"} <= _techs(out)


def test_abuseipdb_exploited_host_emits_t1078() -> None:
    """Cat 20 → T1078. Silently dropped pre-v2."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [20],
    })))
    assert "T1078" in _techs(out)


def test_abuseipdb_open_proxy_emits_t1090() -> None:
    """Cat 9 → T1090. Silently dropped pre-v2."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [9],
    })))
    assert "T1090" in _techs(out)


def test_abuseipdb_vpn_uses_correct_cat_13() -> None:
    """Audit fix: cat 13 (VPN IP), NOT cat 17 — that was the v1 typo."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [13],
    })))
    assert "T1090" in _techs(out)


def test_abuseipdb_cat_17_now_emits_t1566_not_t1090() -> None:
    """Audit fix: cat 17 is Spoofing, not VPN. Now → T1566 (phishing)."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [17],
    })))
    techs = _techs(out)
    assert "T1566" in techs
    assert "T1090" not in techs


def test_abuseipdb_phishing_cat_7_emits_t1566() -> None:
    """New mapping: cat 7 (Phishing) → T1566."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [7],
    })))
    assert "T1566" in _techs(out)


def test_abuseipdb_sql_injection_cat_16_emits_t1190() -> None:
    """New mapping: cat 16 (SQL Injection) → T1190."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 80,
        "abuseipdb_categories": [16],
    })))
    assert "T1190" in _techs(out)


def test_abuseipdb_cat_10_no_longer_emits_ddos() -> None:
    """Audit fix: cat 10 is Web Spam, not DDoS. Used to wrongly fire T1498.
    Cat 10 is intentionally unmapped in v2 — no clean ATT&CK fit at IP layer.
    """
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 95,
        "abuseipdb_categories": [10],
    })))
    assert "T1498" not in _techs(out)


def test_abuseipdb_cat_4_remains_unmapped() -> None:
    """Per A.10: cat 4 (real DDoS) is intentionally dropped — too muddy."""
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 95,
        "abuseipdb_categories": [4],
    })))
    assert _techs(out) == set()


def test_abuseipdb_confidence_scaled_by_score() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 50,
        "abuseipdb_categories": [18],
    })))
    assert out
    for tag in out:
        if tag.technique_id == "T1110":
            assert tag.confidence == pytest.approx(0.35)


def test_abuseipdb_no_categories_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": 95,
    })))
    assert out == []


def test_abuseipdb_score_none_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0054"]).tag(_ev({
        "abuseipdb_score": None,
        "abuseipdb_categories": [18],
    })))
    assert out == []


# ── R0055 GreyNoise — corrected v2 mapping ────────────────────────────


def test_greynoise_scanner_emits_t1595() -> None:
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "scanner",
    })))
    assert "T1595" in _techs(out)


def test_greynoise_c2_tag_emits_both_t1071_and_t1588() -> None:
    """Audit fix: T1588 used to be silently dropped. Now both fire."""
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": ["cobalt_strike"],
    })))
    assert {"T1071", "T1588"} <= _techs(out)


def test_greynoise_tor_exit_emits_t1090() -> None:
    """Audit fix: tor_exit_node → T1090 silently dropped pre-v2."""
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": ["tor_exit_node"],
    })))
    assert "T1090" in _techs(out)


def test_greynoise_ssh_bruteforcer_emits_t1110() -> None:
    """Audit fix: ssh_bruteforcer → T1110 silently dropped pre-v2."""
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": ["ssh_bruteforcer"],
    })))
    assert "T1110" in _techs(out)


def test_greynoise_bare_malicious_emits_t1071_at_half() -> None:
    """Audit gap: bare malicious classification used to emit nothing."""
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": [],
    })))
    techs_by_id = {tag.technique_id: tag for tag in out}
    assert "T1071" in techs_by_id
    # R0055 base T1071 conf is 0.7; bare-malicious multiplier is 0.5 →
    # 0.35. Tags would have fired at 1.0× (0.7).
    assert techs_by_id["T1071"].confidence == pytest.approx(0.35)


def test_greynoise_bare_malicious_does_not_fire_when_specific_tag_present() -> None:
    """Bare-malicious lane is suppressed when a tag already fires T1071
    so we don't double-stamp at conflicting confidence levels."""
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "malicious",
        "greynoise_tags": ["cobalt_strike"],
    })))
    t1071_tags = [t for t in out if t.technique_id == "T1071"]
    assert len(t1071_tags) == 1
    assert t1071_tags[0].confidence == pytest.approx(0.7)  # tag rate, not 0.35


def test_greynoise_benign_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "benign",
        "greynoise_tags": [],
    })))
    assert out == []


def test_greynoise_unknown_tag_with_unknown_classification_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0055"]).tag(_ev({
        "greynoise_classification": "unknown",
        "greynoise_tags": ["random_unmapped"],
    })))
    assert out == []


# ── R0056 Feodo ────────────────────────────────────────────────────


def test_feodo_listed_emits_both() -> None:
    out = asyncio.run(_make_lifter(["R0056"]).tag(_ev({
        "feodo_listed": True,
        "feodo_malware_family": "Emotet",
    })))
    techs = _techs(out)
    assert techs == {"T1071", "T1588"}
    for tag in out:
        assert tag.evidence.get("malware_family") == "Emotet"


def test_feodo_legacy_malware_family_field_still_works() -> None:
    """Tolerate the older payload shape (`malware_family` not prefixed)."""
    out = asyncio.run(_make_lifter(["R0056"]).tag(_ev({
        "feodo_listed": True,
        "malware_family": "Dridex",
    })))
    for tag in out:
        assert tag.evidence.get("malware_family") == "Dridex"


def test_feodo_unlisted_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0056"]).tag(_ev({"feodo_listed": False})))
    assert out == []


def test_feodo_missing_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0056"]).tag(_ev({})))
    assert out == []


# ── R0057 ThreatFox — corrected v2 mapping ─────────────────────────


def test_threatfox_botnet_cc_threat_type_emits_t1071_and_t1588() -> None:
    """Audit fix: ThreatFox keys on threat_type now (was ioc_type). And
    T1588 used to be silently dropped despite being in the mapping."""
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threatfox_threat_types": ["botnet_cc"],
        "threatfox_malware_families": ["sliver"],
    })))
    techs = _techs(out)
    assert {"T1071", "T1588"} <= techs
    for tag in out:
        ev_families = tag.evidence.get("malware_families")
        if ev_families:
            assert "sliver" in ev_families


def test_threatfox_payload_delivery_emits_t1105_and_t1588() -> None:
    """Audit fix: payload_delivery → T1105 silently dropped pre-v2."""
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threatfox_threat_types": ["payload_delivery"],
    })))
    assert {"T1105", "T1588"} <= _techs(out)


def test_threatfox_payload_emits_t1588_only() -> None:
    """New mapping: threat_type=payload (hash-only IOC) → T1588."""
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threatfox_threat_types": ["payload"],
    })))
    assert "T1588" in _techs(out)


def test_threatfox_cc_skimming_emits_t1056() -> None:
    """New mapping: cc_skimming → T1056 (Input Capture)."""
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threatfox_threat_types": ["cc_skimming"],
    })))
    assert "T1056" in _techs(out)


def test_threatfox_legacy_threat_type_singular_still_works() -> None:
    """Tolerate the legacy/test payload shape with a singular field."""
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threat_type": "botnet_cc",
    })))
    assert "T1071" in _techs(out)


def test_threatfox_unknown_threat_type_no_emit() -> None:
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threatfox_threat_types": ["mystery_type"],
    })))
    assert out == []


def test_threatfox_ioc_type_alone_no_longer_drives_techniques() -> None:
    """Audit fix: ioc_type is the indicator format (url/domain/hash) and
    carries no ATT&CK signal. v1 mistakenly keyed on it."""
    out = asyncio.run(_make_lifter(["R0057"]).tag(_ev({
        "threatfox_ioc_types": ["url", "domain"],
        # threat_types intentionally absent
    })))
    assert out == []


# ── R0058 Aggregate bump (no-op in v0) ─────────────────────────────


def test_aggregate_bump_is_inert_in_v0() -> None:
    out = asyncio.run(_make_lifter(["R0058"]).tag(_ev({
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
    # Bases are 0.6–0.7; a clipped state caps each at the 0.5 ceiling —
    # min(base, 0.5) = 0.5 (confidence_max is a ceiling, not a multiplier).
    assert out
    for tag in out:
        assert tag.confidence == pytest.approx(0.5)


# ── Decoupling guard (behavioral counterpart of E.2.7 static check) ─


def test_module_has_no_intel_imports() -> None:
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
