# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-rule unit tests for :class:`CanaryFingerprintLifter` (E.3.11).

Pins the predicates for R0049–R0053 and the
:class:`~decnet.web.db.models.ttp.CanaryFingerprintEvidence` shape
contract — raw fingerprint blobs MUST NOT leak into emitted tags.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
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
        source_kind="canary_fingerprint",
        source_id="src-canary",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload=payload,
    )


def _make_lifter(rule_ids: list[str]) -> CanaryFingerprintLifter:
    rules = [_compile(rid) for rid in rule_ids]
    lifter = CanaryFingerprintLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


@pytest.mark.parametrize(
    "rule_id,payload,techniques",
    [
        ("R0049", {"navigator_webdriver": True}, {"T1059"}),
        (
            "R0050",
            {"canvas_audio_hash_match": "puppeteer"},
            {"T1059", "T1588"},
        ),
        ("R0051", {"webrtc_geo_mismatch": True}, {"T1090"}),
        ("R0052", {"tz_mismatch_zones": 5}, {"T1090"}),
        ("R0052", {"lang_country_mismatch": True}, {"T1090"}),
        ("R0053", {"platform_ua_inconsistent": True}, {"T1036"}),
    ],
)
def test_rule_fires_on_positive(
    rule_id: str,
    payload: dict[str, Any],
    techniques: set[str],
) -> None:
    lifter = _make_lifter([rule_id])
    out = asyncio.run(lifter.tag(_ev(payload)))
    assert out, f"{rule_id} did not fire on positive payload"
    fired = {tag.technique_id for tag in out}
    assert fired == techniques


def test_evidence_shape_only_metric_and_signature() -> None:
    """PII / blob-leak guard: emitted evidence keys ⊆ {metric, matched_signature}.

    Raw canvas hashes, navigator props, full UA strings must NEVER make
    it into TTPTag.evidence — they live on Attacker.fingerprints
    (enrichment), not on the tag (TTP_TAGGING.md §"Hard parts §7").
    """
    lifter = _make_lifter(["R0049"])
    out = asyncio.run(lifter.tag(_ev({
        "navigator_webdriver": True,
        "canvas_hash": "should-not-appear-in-evidence",
        "user_agent": "should-not-appear-in-evidence",
    })))
    assert out
    for tag in out:
        assert set(tag.evidence) <= {"metric", "matched_signature"}, (
            f"unexpected evidence keys: {tag.evidence!r}"
        )


def test_webdriver_false_no_fire() -> None:
    lifter = _make_lifter(["R0049"])
    out = asyncio.run(lifter.tag(_ev({"navigator_webdriver": False})))
    assert out == []


def test_automation_hash_unknown_tool_no_fire() -> None:
    lifter = _make_lifter(["R0050"])
    out = asyncio.run(lifter.tag(_ev({
        "canvas_audio_hash_match": "some_random_browser",
    })))
    assert out == []


def test_tz_below_threshold_no_fire() -> None:
    lifter = _make_lifter(["R0052"])
    out = asyncio.run(lifter.tag(_ev({"tz_mismatch_zones": 1})))
    assert out == []


def test_disabled_state_no_emit() -> None:
    rule = _compile("R0049", RuleState(state="disabled"))
    lifter = CanaryFingerprintLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(_ev({"navigator_webdriver": True})))
    assert out == []


def test_empty_payload_no_errors(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    lifter = _make_lifter(["R0049", "R0050", "R0051", "R0052", "R0053"])
    out = asyncio.run(lifter.tag(_ev({})))
    assert out == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_owns_only_canary_prefix() -> None:
    behavioral = _compile("R0031")
    canary = _compile("R0049")
    lifter = CanaryFingerprintLifter(
        StubRuleStore(compiled=[behavioral, canary]),
    )
    asyncio.run(lifter._index.hydrate_from(
        lifter._store, predicate=lifter._owns,  # type: ignore[arg-type]
    ))
    assert lifter._index.get("R0049") is not None
    assert lifter._index.get("R0031") is None
