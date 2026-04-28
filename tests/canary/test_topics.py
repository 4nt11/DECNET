"""Coverage for the canary bus-topic builder + constants.

The builder shares :func:`_reject_tokens` with every other family in
:mod:`decnet.bus.topics`, so we only need to exercise the canary
surface: the three leaf constants and that bogus segments are
rejected. Anything more would duplicate :mod:`tests.bus.test_topics`.
"""
from __future__ import annotations

import pytest

from decnet.bus import topics


def test_canary_constants_are_distinct() -> None:
    assert topics.CANARY == "canary"
    assert topics.CANARY_PLACED == "placed"
    assert topics.CANARY_TRIGGERED == "triggered"
    assert topics.CANARY_REVOKED == "revoked"
    assert len({
        topics.CANARY_PLACED,
        topics.CANARY_TRIGGERED,
        topics.CANARY_REVOKED,
    }) == 3


def test_canary_builder_round_trip() -> None:
    assert topics.canary("abc-123", topics.CANARY_TRIGGERED) == "canary.abc-123.triggered"
    assert topics.canary("xyz", topics.CANARY_PLACED) == "canary.xyz.placed"
    assert topics.canary("xyz", topics.CANARY_REVOKED) == "canary.xyz.revoked"


@pytest.mark.parametrize("bogus_id", ["", "with.dot", "with*wildcard", "with>chevron", "with space"])
def test_canary_builder_rejects_bad_token_id(bogus_id: str) -> None:
    with pytest.raises(ValueError):
        topics.canary(bogus_id, topics.CANARY_TRIGGERED)


@pytest.mark.parametrize("bogus_event", ["", "x.y", "*", ">"])
def test_canary_builder_rejects_bad_event(bogus_event: str) -> None:
    with pytest.raises(ValueError):
        topics.canary("good_id", bogus_event)
