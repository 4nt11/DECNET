"""Evidence shape contract tests (E.2.1b).

Pins the per-``source_kind`` ``TypedDict`` contract on
:class:`~decnet.web.db.models.ttp.TTPTag.evidence`.

The PII property — ``EmailEvidence`` carries no field for raw rcpt
addresses or body bytes — is GREEN today: it lives in the type, not
in code paths.
"""
from __future__ import annotations

import asyncio
import typing
from pathlib import Path
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
from decnet.ttp.impl.email_lifter import EmailLifter
from decnet.ttp.impl.http_fingerprint_lifter import HttpFingerprintLifter
from decnet.ttp.impl.intel_lifter import IntelLifter
from decnet.ttp.impl.ipv6_leak_lifter import Ipv6LeakLifter
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.filesystem import _parse_and_compile
from decnet.web.db.models.ttp import (
    CanaryFingerprintEvidence,
    CommandEvidence,
    EmailEvidence,
    HttpFingerprintEvidence,
    IntelEvidence,
    Ipv6LinkLocalLeakEvidence,
    TTPTag,
    compute_tag_uuid,
)
from tests.ttp._stub_store import StubRuleStore


_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "ttp"


# ── PII rule §6: type-level, GREEN today ────────────────────────────


def test_email_evidence_excludes_raw_rcpt_and_body() -> None:
    """``EmailEvidence`` MUST NOT carry raw recipient addresses or
    body bytes. The PII discipline lives in the *type* — a lifter that
    tries to leak them fails type-check before it can run.
    """
    keys = (
        EmailEvidence.__required_keys__ | EmailEvidence.__optional_keys__
    )
    assert "rcpt_to_list" not in keys
    assert "body" not in keys


def test_command_evidence_keys() -> None:
    keys = (
        CommandEvidence.__required_keys__ | CommandEvidence.__optional_keys__
    )
    assert keys == {"matched_tokens", "rule_pattern"}


def test_intel_evidence_keys() -> None:
    keys = (
        IntelEvidence.__required_keys__ | IntelEvidence.__optional_keys__
    )
    assert keys == {
        # AbuseIPDB
        "abuseipdb_categories", "abuseipdb_score", "abuse_confidence_score",
        # GreyNoise
        "greynoise_classification", "greynoise_tags", "greynoise_name",
        # Feodo
        "feodo_listed", "feodo_malware_family", "first_seen_feodo", "malware_family",
        # ThreatFox
        "threatfox_threat_types", "threatfox_ioc_types", "threatfox_malware_families",
        "threat_types", "malware_families", "ioc_types",
        # Aggregate meta-rule
        "aggregate_verdict", "bumped_rule_ids",
    }


def test_canary_fingerprint_evidence_keys() -> None:
    keys = (
        CanaryFingerprintEvidence.__required_keys__
        | CanaryFingerprintEvidence.__optional_keys__
    )
    assert keys == {"metric", "matched_signature"}


def test_http_fingerprint_evidence_keys() -> None:
    keys = (
        HttpFingerprintEvidence.__required_keys__
        | HttpFingerprintEvidence.__optional_keys__
    )
    assert keys == {"kind", "hash", "protocol", "client_ip", "seen_at", "raw"}


def test_ipv6_link_local_leak_evidence_keys() -> None:
    keys = (
        Ipv6LinkLocalLeakEvidence.__required_keys__
        | Ipv6LinkLocalLeakEvidence.__optional_keys__
    )
    assert keys == {
        "addr", "mac_oui", "iid_kind", "vector",
        "on_iface", "attacker_v4", "observed_at",
    }


# ── Per-lifter parametrized positive case ───────────────────────────


def _ev(source_kind: str, payload: dict[str, Any]) -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id="src1",
        attacker_uuid="att_1",
        identity_uuid="id_1",
        session_id="sess_1",
        decky_id="decky_1",
        payload=payload,
    )


def _compile_yaml(rule_id: str) -> CompiledRule:
    return _parse_and_compile(_RULES_DIR / f"{rule_id}.yaml", RuleState())


def _hfp_rule() -> CompiledRule:
    """HFP-0001 has no backing YAML — construct it directly."""
    return CompiledRule(
        rule_id="HFP-0001",
        rule_version=1,
        name="scanner_ja4h",
        applies_to=frozenset({"http_fingerprint"}),
        match_spec={},
        emits=(("T1592.002", "T1592", "TA0043", 0.7),),
        evidence_fields=("kind", "hash", "protocol", "client_ip", "seen_at", "raw"),
        state=RuleState(),
    )


_LIFTER_CASES: list[tuple[str, Any, Any, Any, dict[str, Any]]] = [
    (
        "http_fingerprint",
        HttpFingerprintLifter,
        HttpFingerprintEvidence,
        _hfp_rule,
        {"ja4h": "GE11nn0000_cafebabe", "protocol": "h1",
         "client_ip": "10.0.0.1", "seen_at": "2024-01-01T00:00:00Z"},
    ),
    (
        "intel",
        IntelLifter,
        IntelEvidence,
        lambda: _compile_yaml("R0054"),
        {"abuseipdb_score": 90.0, "abuseipdb_categories": [18, 22]},
    ),
    (
        "email",
        EmailLifter,
        EmailEvidence,
        lambda: _compile_yaml("R0042"),
        {"rcpt_count": 30, "body_simhash": "abc123sha256"},
    ),
    (
        "canary_fingerprint",
        CanaryFingerprintLifter,
        CanaryFingerprintEvidence,
        lambda: _compile_yaml("R0049"),
        {"navigator_webdriver": True},
    ),
    (
        "ipv6_leak",
        Ipv6LeakLifter,
        Ipv6LinkLocalLeakEvidence,
        lambda: _compile_yaml("R0059"),
        {
            "addr": "fe80::aabb:ccff:fedd:eeff",
            "mac_oui": "a8:bb:cc",
            "iid_kind": "eui64",
            "vector": "passive_ndp",
            "on_iface": "eth0",
            "attacker_v4": "10.0.0.9",
            "observed_at": "2026-01-01T00:00:00+00:00",
        },
    ),
]


@pytest.mark.parametrize(
    "source_kind, lifter_cls, td_cls, rule_factory, payload",
    _LIFTER_CASES,
    ids=["http_fingerprint", "intel", "email", "canary_fingerprint", "ipv6_leak"],
)
def test_lifter_emits_evidence_matching_typeddict(
    source_kind: str,
    lifter_cls: type[TolerantTagger],
    td_cls: Any,
    rule_factory: Any,
    payload: dict[str, Any],
) -> None:
    """Each lifter's emitted ``evidence`` dict structurally matches
    its ``TypedDict``: keys are a subset of the declared keys and
    runtime types of the present values agree with the hints.
    """
    rule = rule_factory()
    lifter = lifter_cls(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    out = asyncio.run(lifter.tag(_ev(source_kind, payload)))
    assert out, "lifter emitted no tags — cannot verify evidence shape"
    tag = out[0]

    declared = td_cls.__required_keys__ | td_cls.__optional_keys__
    hints = typing.get_type_hints(td_cls)
    for key, value in tag.evidence.items():
        assert key in declared, f"evidence key {key!r} not in {td_cls.__name__}"
        hint = hints.get(key)
        if hint in (str, int, float, bool, list, dict):
            assert isinstance(value, hint)


# ── Negative case: shape violation propagates (impl phase) ──────────


def test_evidence_shape_violation_propagates_as_typeerror() -> None:
    """A lifter that emits an evidence dict with a key not in its
    ``TypedDict`` is a programmer error — it MUST propagate past the
    ``TolerantTagger`` boundary as ``TypeError``, not silently land
    among "absence is normal" swallowed exceptions.
    """

    class BadShapeLifter(TolerantTagger):
        name = "bad_shape"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
            # ``not_in_typeddict`` is not a CommandEvidence key — the
            # tolerant boundary must let this through.
            return [
                TTPTag(
                    uuid=compute_tag_uuid(
                        "command", "src1", "R0001", 1, "T1083", None,
                    ),
                    source_kind="command",
                    source_id="src1",
                    attacker_uuid="att_1",
                    identity_uuid="id_1",
                    tactic="TA0007",
                    technique_id="T1083",
                    confidence=0.5,
                    rule_id="R0001",
                    rule_version=1,
                    evidence={"not_in_typeddict": True},
                    attack_release="enterprise-v15.1",
                )
            ]

    with pytest.raises(TypeError):
        asyncio.run(BadShapeLifter().tag(_ev("command")))
