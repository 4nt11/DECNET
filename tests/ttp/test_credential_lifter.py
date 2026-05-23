# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-rule unit tests for :class:`CredentialLifter` (E.3.13)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.credential_lifter import CredentialLifter
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
        identity_uuid="id1",
        session_id="sess1",
        decky_id="d1",
        payload=payload,
    )


def _make_lifter(rule_ids: list[str]) -> CredentialLifter:
    rules = [_compile(rid) for rid in rule_ids]
    lifter = CredentialLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


# ── R0001 generic auth brute ────────────────────────────────────────


def test_auth_brute_fires_above_threshold() -> None:
    lifter = _make_lifter(["R0001"])
    out = asyncio.run(lifter.tag(_ev("auth_attempt", {
        "fail_count": 12, "service": "ssh",
    })))
    assert len(out) == 1
    assert out[0].technique_id == "T1110"
    assert out[0].evidence["fail_count"] == 12
    assert out[0].evidence["service"] == "ssh"


def test_auth_brute_below_threshold() -> None:
    lifter = _make_lifter(["R0001"])
    assert asyncio.run(lifter.tag(_ev("auth_attempt", {
        "fail_count": 2, "service": "ssh",
    }))) == []


# ── R0002 password guessing ─────────────────────────────────────────


def test_password_guessing_fires() -> None:
    lifter = _make_lifter(["R0002"])
    out = asyncio.run(lifter.tag(_ev("auth_attempt", {
        "username": "root", "password_count": 8,
    })))
    assert len(out) == 1
    assert out[0].sub_technique_id == "T1110.001"
    assert out[0].evidence["password_count"] == 8


def test_password_guessing_no_username() -> None:
    lifter = _make_lifter(["R0002"])
    assert asyncio.run(lifter.tag(_ev("auth_attempt", {
        "password_count": 8,
    }))) == []


# ── R0004 credential reuse ──────────────────────────────────────────


def test_credential_reuse_fires() -> None:
    lifter = _make_lifter(["R0004"])
    out = asyncio.run(lifter.tag(_ev("credential", {
        "credential_hash": "sha256:abc", "reuse_count": 3,
    })))
    assert len(out) == 1
    assert out[0].sub_technique_id == "T1110.004"
    assert out[0].evidence["reuse_count"] == 3


def test_credential_reuse_zero_count() -> None:
    lifter = _make_lifter(["R0004"])
    assert asyncio.run(lifter.tag(_ev("credential", {
        "credential_hash": "sha256:abc", "reuse_count": 0,
    }))) == []


def test_credential_reuse_wrong_source_kind() -> None:
    """R0004 applies_to=credential — an auth_attempt event must not fire it."""
    lifter = _make_lifter(["R0004"])
    assert asyncio.run(lifter.tag(_ev("auth_attempt", {
        "credential_hash": "x", "reuse_count": 5,
    }))) == []


# ── R0005 valid account use ─────────────────────────────────────────


def test_valid_account_requires_prior_brute() -> None:
    lifter = _make_lifter(["R0005"])
    # Successful login but no prior_brute — must not fire.
    assert asyncio.run(lifter.tag(_ev("auth_attempt", {
        "result": "success", "username": "root", "service": "ssh",
    }))) == []
    out = asyncio.run(lifter.tag(_ev("auth_attempt", {
        "result": "success", "prior_brute": True,
        "username": "root", "service": "ssh",
    })))
    assert len(out) == 1
    assert out[0].technique_id == "T1078"


def test_valid_account_failed_login_does_not_fire() -> None:
    lifter = _make_lifter(["R0005"])
    assert asyncio.run(lifter.tag(_ev("auth_attempt", {
        "result": "fail", "prior_brute": True,
        "username": "root", "service": "ssh",
    }))) == []


# ── R0006 default credentials ───────────────────────────────────────


def test_default_credentials_match() -> None:
    lifter = _make_lifter(["R0006"])
    out = asyncio.run(lifter.tag(_ev("auth_attempt", {
        "username": "root", "password": "root", "service": "ssh",
    })))
    assert len(out) == 1
    assert out[0].sub_technique_id == "T1078.001"
    assert out[0].evidence["username"] == "root"


def test_default_credentials_no_match() -> None:
    lifter = _make_lifter(["R0006"])
    assert asyncio.run(lifter.tag(_ev("auth_attempt", {
        "username": "root", "password": "hunter2", "service": "ssh",
    }))) == []


# ── State modulation (one rule covers the path) ─────────────────────


def test_disabled_rule_skipped() -> None:
    rule = _compile("R0004", RuleState(state="disabled"))
    lifter = CredentialLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    assert asyncio.run(lifter.tag(_ev("credential", {
        "credential_hash": "x", "reuse_count": 3,
    }))) == []


def test_clipped_rule_caps_confidence() -> None:
    rule = _compile("R0004", RuleState(state="clipped", confidence_max=0.5))
    lifter = CredentialLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(_ev("credential", {
        "credential_hash": "x", "reuse_count": 3,
    })))
    assert len(out) == 1
    # Base 0.9 × 0.5 ceiling.
    assert out[0].confidence == pytest.approx(0.45)


# ── Ownership predicate ─────────────────────────────────────────────


def test_owns_skips_foreign_prefix() -> None:
    """Lifter must not pick up rules whose match.kind is in another lifter's prefix."""
    behavioral_rule = _compile("R0031")  # lifter:behavioral_beaconing
    assert not CredentialLifter._owns(behavioral_rule)
    own = _compile("R0001")
    assert CredentialLifter._owns(own)


# ── Idempotency ─────────────────────────────────────────────────────


def test_replay_produces_same_tag_uuid() -> None:
    lifter = _make_lifter(["R0001"])
    payload = {"fail_count": 12, "service": "ssh"}
    a = asyncio.run(lifter.tag(_ev("auth_attempt", payload)))
    b = asyncio.run(lifter.tag(_ev("auth_attempt", payload)))
    assert [t.uuid for t in a] == [t.uuid for t in b]
