# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every TTPTag emitted via ``emit_tags()`` carries a populated ``mitre_url`` column.

Phase 3 promoted ``mitre_url`` from a JSON evidence field to a
first-class TTPTag column populated at construction. The two
construction sites are ``decnet/ttp/impl/_emit.py`` (the lifter
choke point) and the inline path in ``rule_engine._evaluate_rules``;
both look up :func:`decnet.ttp.attack_stix.mitre_url_for`.

Also covers the regression-net: intel_lifter's evidence dicts must
NOT carry a ``mitre_url`` key (the column is canonical now —
duplicating in the JSON column drifts when the bundle moves).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from decnet.ttp import attack_stix
from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "decnet" / "data" / "enterprise-attack-19.1.json"


@pytest.fixture(autouse=True)
def _pin_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    license_path = tmp_path / "LICENSE.txt"
    license_path.write_text("placeholder", encoding="utf-8")
    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(_REPO_BUNDLE))
    monkeypatch.setenv("DECNET_ATTACK_LICENSE", str(license_path))
    attack_stix._data = None
    attack_stix._loaded_path = None
    attack_stix._attack_pattern_by_id.cache_clear()
    attack_stix._tactic_by_id.cache_clear()
    attack_stix._tactic_by_short_name.cache_clear()
    attack_stix.groups_using_technique.cache_clear()


def _rule(emits: tuple[tuple[str, str | None, str, float], ...]) -> CompiledRule:
    return CompiledRule(
        rule_id="R-test",
        rule_version=1,
        name="test rule",
        applies_to=frozenset({"command"}),
        match_spec={"pattern": "test"},
        emits=emits,
        evidence_fields=("matched_tokens",),
        state=RuleState(),
    )


def _event() -> TaggerEvent:
    return TaggerEvent(
        source_kind="command",
        source_id="cmd-1",
        attacker_uuid="att-uuid",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={"matched_tokens": ["hydra"]},
    )


def test_emit_tags_attaches_mitre_url_for_top_level_technique() -> None:
    rule = _rule((("T1110", None, "TA0006", 0.85),))
    tags = emit_tags(rule, _event(), evidence={"matched_tokens": ["hydra"]})
    assert len(tags) == 1
    assert tags[0].mitre_url == "https://attack.mitre.org/techniques/T1110"


def test_emit_tags_attaches_subtechnique_url_when_subtechnique_present() -> None:
    rule = _rule((("T1059", "T1059.004", "TA0002", 0.9),))
    tags = emit_tags(rule, _event(), evidence={"matched_tokens": ["sh"]})
    assert tags[0].mitre_url == "https://attack.mitre.org/techniques/T1059/004"


def test_emit_tags_mitre_url_none_for_unknown_technique() -> None:
    rule = _rule((("T9999", None, "TA0001", 0.5),))
    tags = emit_tags(rule, _event(), evidence={"matched_tokens": ["x"]})
    assert tags[0].mitre_url is None


def test_emit_tags_per_emit_resolves_independently() -> None:
    """Multi-emit rule: each emit slot resolves its own URL."""
    rule = _rule((
        ("T1110", None, "TA0006", 0.85),
        ("T1059", "T1059.004", "TA0002", 0.9),
    ))
    tags = emit_tags(rule, _event(), evidence={"matched_tokens": ["x"]})
    urls = [t.mitre_url for t in tags]
    assert "https://attack.mitre.org/techniques/T1110" in urls
    assert "https://attack.mitre.org/techniques/T1059/004" in urls


def test_intel_lifter_evidence_does_not_contain_mitre_url() -> None:
    """Regression: mitre_url lives on the column, not in the evidence JSON.

    Calls each provider's decision function directly with a payload
    that should produce emits, then asserts no resulting evidence-extra
    dict contains a ``mitre_url`` key.
    """
    from decnet.ttp.data import intel_loader
    from decnet.ttp.impl import intel_lifter

    intel_loader.clear_cache()
    intel_lifter._mapping.cache_clear()

    decisions: list[tuple[str, dict[str, Any]]] = [
        (
            "abuseipdb",
            {"abuseipdb_score": 95, "abuseipdb_categories": [5, 22]},
        ),
        (
            "greynoise",
            {
                "greynoise_classification": "scanner",
                "greynoise_tags": ["tor_exit_node", "ssh_bruteforcer"],
            },
        ),
        ("threatfox", {"threatfox_threat_types": ["botnet_cc"]}),
        ("feodo", {"feodo_listed": True, "feodo_malware_family": "Emotet"}),
    ]

    fns = {
        "abuseipdb": intel_lifter._abuseipdb_decisions,
        "greynoise": intel_lifter._greynoise_decisions,
        "threatfox": intel_lifter._threatfox_decisions,
        "feodo": intel_lifter._feodo_decisions,
    }
    for provider, payload in decisions:
        emits = fns[provider]({}, payload)
        assert emits, f"{provider}: expected at least one emit"
        for _tech, _mult, evidence_extra in emits:
            assert "mitre_url" not in evidence_extra, (
                f"{provider}: evidence_extra still carries mitre_url "
                f"(should live on TTPTag.mitre_url column instead): "
                f"{evidence_extra}"
            )
