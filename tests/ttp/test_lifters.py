"""Contract tests for the six per-source lifters (E.1.6).

Scoped to the contract surface: each lifter is a :class:`TolerantTagger`
subclass with a non-empty ``HANDLES`` ⊆ :data:`KNOWN_SOURCE_KINDS`,
unique ``name``, and an empty-list return from ``_tag_impl``. Behavioral
absence-tolerance assertions from E.2.6 (per-provider null patterns,
session-without-AttackerBehavior, etc.) are present but xfail-strict
pending E.3.
"""
from __future__ import annotations

import asyncio

import pytest

from decnet.ttp.base import KNOWN_SOURCE_KINDS, TaggerEvent, TolerantTagger
from decnet.ttp.impl.behavioral_lifter import BehavioralLifter
from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
from decnet.ttp.impl.credential_lifter import CredentialLifter
from decnet.ttp.impl.email_lifter import EmailLifter
from decnet.ttp.impl.identity_lifter import IdentityLifter
from decnet.ttp.impl.intel_lifter import IntelLifter
from tests.ttp._stub_store import StubRuleStore


def _instantiate(cls: type[TolerantTagger]) -> TolerantTagger:
    """Every shipped lifter (E.3.9–E.3.13) takes a :class:`RuleStore`."""
    return cls(StubRuleStore())  # type: ignore[call-arg]

ALL_LIFTERS = [
    BehavioralLifter,
    IntelLifter,
    EmailLifter,
    CanaryFingerprintLifter,
    IdentityLifter,
    CredentialLifter,
]


def _ev(source_kind: str) -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={},
    )


@pytest.mark.parametrize("cls", ALL_LIFTERS)
def test_lifter_subclasses_tolerant_tagger(cls):
    assert issubclass(cls, TolerantTagger)


@pytest.mark.parametrize("cls", ALL_LIFTERS)
def test_lifter_handles_is_non_empty_frozenset_subset_of_known(cls):
    assert isinstance(cls.HANDLES, frozenset)
    assert cls.HANDLES, f"{cls.__name__}.HANDLES must not be empty"
    assert cls.HANDLES <= KNOWN_SOURCE_KINDS, (
        f"{cls.__name__}.HANDLES contains kinds not in KNOWN_SOURCE_KINDS"
    )


def test_lifter_names_are_unique_and_non_empty():
    names = [cls.name for cls in ALL_LIFTERS]
    assert all(n for n in names), "every lifter needs a non-empty name"
    assert len(set(names)) == len(names), "lifter names must be unique"


@pytest.mark.parametrize("cls", ALL_LIFTERS)
def test_lifter_tag_returns_empty_list_for_handled_event(cls):
    lifter = _instantiate(cls)
    kind = next(iter(cls.HANDLES))
    out = asyncio.run(lifter.tag(_ev(kind)))
    assert out == []


@pytest.mark.parametrize("cls", ALL_LIFTERS)
def test_lifter_instantiable(cls):
    # No abstract methods left — concrete subclass must be constructible.
    _instantiate(cls)


# ── E.2.6 deferred absence-tolerance behavior ──────────────────────


def test_e26_intel_lifter_partial_provider_nulls():
    """E.3.10: with no actionable per-provider signal (e.g. score set
    but categories absent), IntelLifter returns []. No errors."""
    lifter = IntelLifter(StubRuleStore())
    out = asyncio.run(lifter.tag(_ev("intel")))
    assert out == []


def test_e26_behavioral_lifter_no_attacker_behavior_row():
    """E.3.9: a session event with no AttackerBehavior fields populated
    must produce zero tags and zero errors. Was xfail-strict before
    BehavioralLifter shipped; now a real assertion."""
    lifter = BehavioralLifter(StubRuleStore())
    out = asyncio.run(lifter.tag(_ev("session")))
    assert out == []
