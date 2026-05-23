# SPDX-License-Identifier: AGPL-3.0-or-later
"""MazeNET status state-machine tests.

Every legal transition declared in the plan is permitted; every other
pair (including self-loops and unknowns) must raise.
"""
import pytest
from decnet.topology.status import (
    TopologyStatus,
    TopologyStatusError,
    assert_transition,
    legal_next,
)

LEGAL = {
    (TopologyStatus.PENDING, TopologyStatus.DEPLOYING),
    (TopologyStatus.PENDING, TopologyStatus.TORN_DOWN),
    (TopologyStatus.DEPLOYING, TopologyStatus.ACTIVE),
    (TopologyStatus.DEPLOYING, TopologyStatus.FAILED),
    (TopologyStatus.DEPLOYING, TopologyStatus.DEGRADED),
    (TopologyStatus.DEPLOYING, TopologyStatus.TEARING_DOWN),
    (TopologyStatus.ACTIVE, TopologyStatus.DEGRADED),
    (TopologyStatus.ACTIVE, TopologyStatus.TEARING_DOWN),
    (TopologyStatus.DEGRADED, TopologyStatus.ACTIVE),
    (TopologyStatus.DEGRADED, TopologyStatus.TEARING_DOWN),
    (TopologyStatus.FAILED, TopologyStatus.TEARING_DOWN),
    (TopologyStatus.TEARING_DOWN, TopologyStatus.TORN_DOWN),
    (TopologyStatus.TEARING_DOWN, TopologyStatus.DEGRADED),
}


def test_every_legal_transition_permitted():
    for cur, nxt in LEGAL:
        assert_transition(cur, nxt)  # no raise


def test_every_illegal_transition_raises():
    for cur in TopologyStatus.ALL:
        for nxt in TopologyStatus.ALL:
            if (cur, nxt) in LEGAL:
                continue
            with pytest.raises(TopologyStatusError):
                assert_transition(cur, nxt)


def test_torn_down_is_terminal():
    assert legal_next(TopologyStatus.TORN_DOWN) == frozenset()


def test_unknown_status_raises():
    with pytest.raises(TopologyStatusError):
        assert_transition("pending", "bogus")
    with pytest.raises(TopologyStatusError):
        assert_transition("bogus", "active")
    with pytest.raises(TopologyStatusError):
        legal_next("bogus")
