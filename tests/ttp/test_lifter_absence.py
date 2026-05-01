"""E.2.6 — "Tolerates absence" per-lifter conformance.

Every per-source lifter is allowed (and expected) to encounter
events whose required join is missing — no ``AttackerIntel`` row,
no ``SessionProfile``, no ``AttackerBehavior``, no canary record,
no identity row, no ``CredentialReuse`` entry. Absence is the
steady state, not the exception. The contract pinned here:

* ``await lifter.tag(event)`` returns ``[]``.
* No ``ERROR`` log records are produced (``WARNING`` and below
  are tolerated; the absence of ``ERROR`` is the load-bearing
  property).

Today every lifter's ``_tag_impl`` returns ``[]`` outright, so
these assertions pass directly. When E.3.6 fills the bodies,
these tests stay green — they pin the property the impl must
preserve. The "intel lifter populated → emits tags" expectation
is parked behind ``xfail(strict=True)`` so the trip-wire flips
the day intel_lifter starts emitting.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl.behavioral_lifter import BehavioralLifter
from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
from decnet.ttp.impl.credential_lifter import CredentialLifter
from decnet.ttp.impl.email_lifter import EmailLifter
from decnet.ttp.impl.identity_lifter import IdentityLifter
from decnet.ttp.impl.intel_lifter import IntelLifter


def _ev(source_kind: str, payload: dict[str, Any] | None = None) -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid="id1",
        session_id="sess1",
        decky_id="d1",
        payload=payload or {},
    )


# Each entry: (lifter class, source_kind matching the lifter's domain,
# empty-join payload — i.e. payload that points at a row that does
# not exist in the DB / has no enrichment yet). Per the design doc
# every lifter must return [] and emit zero ERROR records when its
# required upstream is absent.
_LIFTER_CASES: list[tuple[type[TolerantTagger], str, dict[str, Any]]] = [
    # behavioral_lifter joins on AttackerBehavior — empty: no row exists yet
    (BehavioralLifter, "session", {"attacker_uuid": "att-not-in-db"}),
    # intel_lifter joins on AttackerIntel — empty payload, no enrichment
    (IntelLifter, "intel", {"attacker_uuid": "att-no-intel"}),
    # email_lifter consumes email-bus payloads; empty headers/body
    (EmailLifter, "email", {"headers": {}, "rcpt_count": 0, "body_hash": ""}),
    # canary_fingerprint joins on canary-derived rows — none yet
    (CanaryFingerprintLifter, "canary_fingerprint", {"token_id": "no-such"}),
    # identity_lifter rolls up cross-attacker identity facts — none
    (IdentityLifter, "identity", {"identity_uuid": "id-empty"}),
    # credential_lifter joins on CredentialReuse — none
    (CredentialLifter, "credential", {"credential_id": "cred-no-reuse"}),
]


@pytest.mark.parametrize("lifter_cls,source_kind,payload", _LIFTER_CASES)
def test_lifter_tolerates_absence(
    lifter_cls: type[TolerantTagger],
    source_kind: str,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    lifter = lifter_cls()
    out = asyncio.run(lifter.tag(_ev(source_kind, payload)))
    assert out == []
    # The load-bearing property: no ERROR-or-above records. WARNING
    # is fine (and is what TolerantTagger uses on swallowed
    # exceptions); ERROR would page someone for the steady state.
    assert not [
        r for r in caplog.records if r.levelno >= logging.ERROR
    ], f"{lifter_cls.__name__} produced ERROR records on absent join"


# ─── intel_lifter per-provider null parametrization ──────────────────────────


# Per the spec: parametrize over per-provider null patterns. Each
# shape returns [] today (the lifter body is empty); when E.3.6
# wires real provider score logic, the "all populated" case grows
# to a non-empty result and trips the corresponding xfail.
_INTEL_NULL_PATTERNS: list[tuple[str, dict[str, Any]]] = [
    ("only_greynoise_null", {
        "attacker_uuid": "att1",
        "abuseipdb_score": 95,
        "greynoise_classification": None,
    }),
    ("only_abuseipdb_null", {
        "attacker_uuid": "att1",
        "abuseipdb_score": None,
        "greynoise_classification": "malicious",
    }),
    ("all_null", {
        "attacker_uuid": "att1",
        "abuseipdb_score": None,
        "greynoise_classification": None,
    }),
]


@pytest.mark.parametrize("name,payload", _INTEL_NULL_PATTERNS)
def test_intel_lifter_partial_null_returns_no_error(
    name: str,
    payload: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    out = asyncio.run(IntelLifter().tag(_ev("intel", payload)))
    # Every partial-null shape produces zero tags today and zero
    # ERROR records — the contract this commit pins. (When E.3.6
    # ships, only the "all populated" shape graduates to non-empty;
    # the partial-null shapes stay [] forever.)
    assert out == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.6: intel_lifter does not yet emit tags",
)
def test_intel_lifter_all_populated_emits_tags() -> None:
    """When AbuseIPDB AND GreyNoise both return verdicts, intel_lifter
    must emit at least one tag. Strict-xfail today; flips when impl
    lands."""
    payload = {
        "attacker_uuid": "att1",
        "abuseipdb_score": 95,
        "greynoise_classification": "malicious",
    }
    out = asyncio.run(IntelLifter().tag(_ev("intel", payload)))
    assert len(out) >= 1
