"""Per-rule unit tests for :class:`EmailLifter` (E.3.12).

Pins R0041–R0048 predicates and the EmailEvidence PII discipline:
emitted ``TTPTag.evidence`` MUST NOT contain raw addresses, raw body
bytes, or full URLs (only hashed / domain / matched-discriminator
forms are permitted).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.email_lifter import (
    _EMAIL_EVIDENCE_ALLOWED_KEYS,
    EmailLifter,
)
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
        source_kind="email",
        source_id="src-email",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload=payload,
    )


def _make_lifter(rule_ids: list[str]) -> EmailLifter:
    rules = [_compile(rid) for rid in rule_ids]
    lifter = EmailLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


# ── Per-rule positives ─────────────────────────────────────────────


def test_open_relay_fires_on_high_rcpt_foreign_from() -> None:
    lifter = _make_lifter(["R0041"])
    out = asyncio.run(lifter.tag(_ev({
        "rcpt_count": 50,
        "from_domain": "victim.example",
        "mail_from_domain": "evil.example",
        "rcpt_domains": ["target1.example", "target2.example"],
        "body_sha256": "a" * 64,
    })))
    techs = {tag.technique_id for tag in out}
    assert {"T1496", "T1586"} <= techs


def test_open_relay_no_fire_on_matching_from() -> None:
    lifter = _make_lifter(["R0041"])
    out = asyncio.run(lifter.tag(_ev({
        "rcpt_count": 50,
        "from_domain": "same.example",
        "mail_from_domain": "same.example",
    })))
    assert out == []


def test_mass_phish_fires_on_threshold_with_simhash() -> None:
    lifter = _make_lifter(["R0042"])
    out = asyncio.run(lifter.tag(_ev({
        "rcpt_count": 100,
        "body_simhash": "abc123",
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1566" in techs


def test_mass_phish_no_simhash_no_fire() -> None:
    """High RCPT alone is open-relay territory; campaign needs simhash."""
    lifter = _make_lifter(["R0042"])
    out = asyncio.run(lifter.tag(_ev({"rcpt_count": 100})))
    assert out == []


def test_xmailer_kit_fires_with_match() -> None:
    lifter = _make_lifter(["R0043"])
    out = asyncio.run(lifter.tag(_ev({
        "x_mailer": "PHPMailer 6.0 (kit-X)",
        "matched_kit": "kit-X",
    })))
    techs = {tag.technique_id for tag in out}
    assert {"T1566", "T1588"} <= techs


def test_xmailer_kit_no_match_no_fire() -> None:
    lifter = _make_lifter(["R0043"])
    out = asyncio.run(lifter.tag(_ev({"x_mailer": "Outlook 16.0"})))
    assert out == []


def test_idn_url_fires_on_punycode() -> None:
    lifter = _make_lifter(["R0044"])
    out = asyncio.run(lifter.tag(_ev({
        "urls": ["https://xn--80ak6aa92e.com/login"],
    })))
    techs = {tag.technique_id for tag in out}
    assert {"T1036", "T1566"} <= techs


def test_sender_masquerade_from_returnpath_mismatch() -> None:
    lifter = _make_lifter(["R0045"])
    out = asyncio.run(lifter.tag(_ev({
        "from_domain": "ceo@victim.example",
        "return_path_domain": "evil.example",
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1036" in techs


def test_sender_masquerade_dkim_fail() -> None:
    lifter = _make_lifter(["R0045"])
    out = asyncio.run(lifter.tag(_ev({
        "dkim_signed": False,
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1036" in techs


def test_malicious_attachment_macro() -> None:
    lifter = _make_lifter(["R0046"])
    out = asyncio.run(lifter.tag(_ev({
        "attachment_macros": True,
        "attachment_sha256s": ["b" * 64],
    })))
    techs = {tag.technique_id for tag in out}
    assert {"T1204", "T1566"} <= techs


def test_malicious_attachment_lnk_extension() -> None:
    lifter = _make_lifter(["R0046"])
    out = asyncio.run(lifter.tag(_ev({
        "attachment_extensions": [".lnk"],
        "attachment_sha256s": ["c" * 64],
    })))
    techs = {tag.technique_id for tag in out}
    assert {"T1204", "T1566"} <= techs


def test_bec_subject_and_body_match() -> None:
    lifter = _make_lifter(["R0047"])
    out = asyncio.run(lifter.tag(_ev({
        "subject": "URGENT wire transfer needed",
        "body_text": "Please send $50k immediately, this is confidential.",
    })))
    techs = {tag.technique_id for tag in out}
    assert "T1566" in techs


def test_bec_no_body_action_no_fire() -> None:
    lifter = _make_lifter(["R0047"])
    out = asyncio.run(lifter.tag(_ev({
        "subject": "URGENT review",
        "body_text": "Please review the attached doc.",
    })))
    assert out == []


def test_encoded_payload_fires_on_precomputed_count() -> None:
    lifter = _make_lifter(["R0048"])
    out = asyncio.run(lifter.tag(_ev({
        "body_text": "small body text",
        "body_base64_bytes": 8192,
    })))
    techs = {tag.technique_id for tag in out}
    assert {"T1071", "T1027"} <= techs


def test_encoded_payload_below_threshold_no_fire() -> None:
    lifter = _make_lifter(["R0048"])
    out = asyncio.run(lifter.tag(_ev({
        "body_text": "small body",
        "body_base64_bytes": 100,
    })))
    assert out == []


# ── PII discipline ─────────────────────────────────────────────────


def test_evidence_keys_subset_of_email_evidence_allowlist() -> None:
    """No predicate may leak raw addresses, body bytes, or full URLs."""
    lifter = _make_lifter([
        "R0041", "R0042", "R0043", "R0044",
        "R0045", "R0046", "R0047", "R0048",
    ])
    payloads = [
        {
            "rcpt_count": 50,
            "from_domain": "ceo@victim.example",
            "mail_from_domain": "evil.example",
            "return_path_domain": "evil.example",
            "rcpt_domains": ["a.example"],
            "x_mailer": "Outlook 16",
            "matched_kit": "kit-Y",
            "urls": ["https://xn--example.test/path?id=secret"],
            "dkim_signed": False,
            "spf_pass": False,
            "attachment_macros": True,
            "attachment_extensions": [".lnk"],
            "attachment_sha256s": ["d" * 64],
            "subject": "URGENT wire",
            "body_text": "please send transfer immediately",
            "body_base64_bytes": 8192,
        },
    ]
    for payload in payloads:
        out = asyncio.run(lifter.tag(_ev(payload)))
        for tag in out:
            disallowed = set(tag.evidence) - _EMAIL_EVIDENCE_ALLOWED_KEYS
            assert not disallowed, (
                f"PII leak in {tag.rule_id}: unexpected keys {disallowed}"
            )


def test_evidence_carries_no_raw_addresses_or_body() -> None:
    lifter = _make_lifter(["R0041", "R0045", "R0047"])
    out = asyncio.run(lifter.tag(_ev({
        "rcpt_count": 50,
        "from_domain": "ceo-direct@victim.example",  # full address-shaped
        "mail_from_domain": "evil.example",
        "return_path_domain": "evil.example",
        "subject": "URGENT wire transfer needed",
        "body_text": "Send the wire to acct 12345 confidential right now",
        "rcpt_domains": ["target.example"],
    })))
    assert out
    for tag in out:
        as_str = repr(tag.evidence)
        assert "ceo-direct@" not in as_str
        assert "Send the wire" not in as_str
        assert "12345" not in as_str


def test_body_sha_set_when_upstream_omits() -> None:
    lifter = _make_lifter(["R0042"])
    out = asyncio.run(lifter.tag(_ev({
        "rcpt_count": 100,
        "body_text": "some body",
        "body_simhash": "abc",
    })))
    assert out
    expected = hashlib.sha256(b"some body").hexdigest()
    for tag in out:
        assert tag.evidence["body_sha256"] == expected


# ── State + tolerance ──────────────────────────────────────────────


def test_disabled_email_rule_no_emit() -> None:
    rule = _compile("R0042", RuleState(state="disabled"))
    lifter = EmailLifter(StubRuleStore())
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(_ev({
        "rcpt_count": 200, "body_simhash": "abc",
    })))
    assert out == []


def test_empty_payload_no_errors(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    lifter = _make_lifter([
        "R0041", "R0042", "R0043", "R0044",
        "R0045", "R0046", "R0047", "R0048",
    ])
    out = asyncio.run(lifter.tag(_ev({})))
    assert out == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_owns_only_email_prefix() -> None:
    behavioral = _compile("R0031")
    email = _compile("R0041")
    lifter = EmailLifter(StubRuleStore(compiled=[behavioral, email]))
    asyncio.run(lifter._index.hydrate_from(
        lifter._store, predicate=lifter._owns,  # type: ignore[arg-type]
    ))
    assert lifter._index.get("R0041") is not None
    assert lifter._index.get("R0031") is None
