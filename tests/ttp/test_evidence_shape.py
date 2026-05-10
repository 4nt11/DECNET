"""Evidence shape contract tests (E.2.1b).

Pins the per-``source_kind`` ``TypedDict`` contract on
:class:`~decnet.web.db.models.ttp.TTPTag.evidence`.

Two halves of the contract live behind ``xfail(strict=True)`` because
they require behavior that lands in the implementation phase (E.3.x):

* lifters currently return ``[]``, so the parametrized positive case
  cannot sample real evidence dicts;
* :class:`~decnet.ttp.base.TolerantTagger` currently swallows every
  ``Exception``, so the "shape violation propagates as ``TypeError``"
  contract has not been wired in yet.

The PII property — ``EmailEvidence`` carries no field for raw rcpt
addresses or body bytes — is GREEN today: it lives in the type, not
in code paths.
"""
from __future__ import annotations

import asyncio
import typing
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl.behavioral_lifter import BehavioralLifter
from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
from decnet.ttp.impl.email_lifter import EmailLifter
from decnet.ttp.impl.http_fingerprint_lifter import HttpFingerprintLifter
from decnet.ttp.impl.intel_lifter import IntelLifter
from decnet.web.db.models.ttp import (
    CanaryFingerprintEvidence,
    CommandEvidence,
    EmailEvidence,
    HttpFingerprintEvidence,
    IntelEvidence,
    TTPTag,
    compute_tag_uuid,
)


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
    assert keys == {"intel_uuid", "provider", "category", "score"}


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


# ── Per-lifter parametrized positive case (impl phase) ──────────────


def _ev(source_kind: str) -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id="src1",
        attacker_uuid="att_1",
        identity_uuid="id_1",
        session_id="sess_1",
        decky_id="decky_1",
        payload={},
    )


_LIFTER_CASES = [
    ("command", BehavioralLifter, CommandEvidence),
    ("intel", IntelLifter, IntelEvidence),
    ("email", EmailLifter, EmailEvidence),
    ("canary_fingerprint", CanaryFingerprintLifter, CanaryFingerprintEvidence),
]


@pytest.mark.xfail(strict=True, reason="impl phase E.3.x: lifters return [] today")
@pytest.mark.parametrize("source_kind, lifter_cls, td_cls", _LIFTER_CASES)
def test_lifter_emits_evidence_matching_typeddict(
    source_kind: str,
    lifter_cls: type[TolerantTagger],
    td_cls: Any,
) -> None:
    """Each lifter's emitted ``evidence`` dict structurally matches
    its ``TypedDict``: keys are a subset of the declared keys and
    runtime types of the present values agree with the hints.
    """
    lifter = lifter_cls()
    out = asyncio.run(lifter.tag(_ev(source_kind)))
    assert out, "lifter emitted no tags — cannot verify evidence shape"
    tag = out[0]

    declared = td_cls.__required_keys__ | td_cls.__optional_keys__
    hints = typing.get_type_hints(td_cls)
    for key, value in tag.evidence.items():
        assert key in declared, f"evidence key {key!r} not in {td_cls.__name__}"
        # Soft type check: only compare against concrete types in the
        # hint where introspection makes sense. This avoids tangling
        # with Literal / Optional resolution for the contract test.
        hint = hints.get(key)
        if hint in (str, int, float, bool, list, dict):
            assert isinstance(value, hint)


# ── Negative case: shape violation propagates (impl phase) ──────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase: TolerantTagger currently swallows TypeError",
)
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
