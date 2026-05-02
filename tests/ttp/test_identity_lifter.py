"""Per-rule unit tests for :class:`IdentityLifter` (E.3.13).

Identity-rollup tags carry ``identity_uuid`` populated and
``attacker_uuid=NULL`` per the design doc's worked example —
asserted explicitly here.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.identity_lifter import IdentityLifter
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
        source_kind="identity",
        source_id="src-identity",
        attacker_uuid="att-irrelevant",
        identity_uuid="id-spray-1",
        session_id=None,
        decky_id=None,
        payload=payload,
    )


def _make_lifter(rule_ids: list[str]) -> IdentityLifter:
    rules = [_compile(rid) for rid in rule_ids]
    lifter = IdentityLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


# ── R0003 password spraying ─────────────────────────────────────────


def test_password_spraying_fires_when_threshold_met() -> None:
    lifter = _make_lifter(["R0003"])
    payload = {"shared_password_hash": "deadbeef", "account_count": 5}
    out = asyncio.run(lifter.tag(_ev(payload)))
    assert len(out) == 1
    tag = out[0]
    assert tag.technique_id == "T1110"
    assert tag.sub_technique_id == "T1110.003"
    assert tag.tactic == "TA0006"
    # Identity-rollup invariant: tag belongs to the Identity, never
    # to one member IP.
    assert tag.attacker_uuid is None
    assert tag.identity_uuid == "id-spray-1"
    assert tag.evidence["shared_password_hash"] == "deadbeef"
    assert tag.evidence["account_count"] == 5


def test_password_spraying_below_threshold() -> None:
    lifter = _make_lifter(["R0003"])
    # account_threshold is 3; account_count=2 must not fire.
    payload = {"shared_password_hash": "deadbeef", "account_count": 2}
    assert asyncio.run(lifter.tag(_ev(payload))) == []


def test_password_spraying_missing_hash() -> None:
    lifter = _make_lifter(["R0003"])
    payload = {"account_count": 9}
    assert asyncio.run(lifter.tag(_ev(payload))) == []


def test_password_spraying_wrong_source_kind() -> None:
    """Rule applies_to=identity; an event with source_kind=session is ignored."""
    lifter = _make_lifter(["R0003"])
    ev = _ev({"shared_password_hash": "x", "account_count": 9})._replace(
        source_kind="session",
    )
    assert asyncio.run(lifter.tag(ev)) == []


# ── State modulation ────────────────────────────────────────────────


def test_disabled_rule_does_not_fire() -> None:
    rule = _compile("R0003", RuleState(state="disabled"))
    lifter = IdentityLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    payload = {"shared_password_hash": "x", "account_count": 9}
    assert asyncio.run(lifter.tag(_ev(payload))) == []


def test_clipped_rule_caps_confidence() -> None:
    rule = _compile(
        "R0003",
        RuleState(state="clipped", confidence_max=0.5),
    )
    lifter = IdentityLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    payload = {"shared_password_hash": "x", "account_count": 9}
    out = asyncio.run(lifter.tag(_ev(payload)))
    assert len(out) == 1
    # Base confidence 0.9 × 0.5 ceiling clamp.
    assert out[0].confidence == pytest.approx(0.45)


def test_expired_rule_does_not_fire() -> None:
    expired = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    rule = _compile(
        "R0003",
        RuleState(state="enabled", expires_at=expired),
    )
    lifter = IdentityLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    payload = {"shared_password_hash": "x", "account_count": 9}
    assert asyncio.run(lifter.tag(_ev(payload))) == []


# ── Idempotency ─────────────────────────────────────────────────────


def test_replay_produces_same_tag_uuid() -> None:
    """Same source event replayed → identical tag UUID (idempotent)."""
    lifter = _make_lifter(["R0003"])
    payload = {"shared_password_hash": "deadbeef", "account_count": 5}
    a = asyncio.run(lifter.tag(_ev(payload)))
    b = asyncio.run(lifter.tag(_ev(payload)))
    assert [t.uuid for t in a] == [t.uuid for t in b]
