"""Tests for the topic hierarchy builders."""
from __future__ import annotations

import pytest

from decnet.bus import topics


def test_topology_mutation_builder() -> None:
    topic = topics.topology_mutation("abc123", topics.MUTATION_APPLIED)
    assert topic == "topology.abc123.mutation.applied"


def test_topology_status_builder() -> None:
    assert topics.topology_status("t-1") == "topology.t-1.status"


def test_decky_builder() -> None:
    assert topics.decky("d-42", topics.DECKY_STATE) == "decky.d-42.state"
    assert topics.decky("d-42", topics.DECKY_TRAFFIC) == "decky.d-42.traffic"


def test_system_builder_allows_dotted_leaf() -> None:
    # system.bus.health has a dot in the leaf — that's intentional and a
    # legitimate hierarchy refinement, not a segment violation.
    assert topics.system(topics.SYSTEM_BUS_HEALTH) == "system.bus.health"
    assert topics.system(topics.SYSTEM_LOG) == "system.log"


def test_system_builder_rejects_empty() -> None:
    with pytest.raises(ValueError):
        topics.system("")


@pytest.mark.parametrize("bad", ["", "has.dot", "has*wildcard", "has>wild", "with space", "with\ttab"])
def test_segment_validation(bad: str) -> None:
    with pytest.raises(ValueError):
        topics.topology_mutation(bad, topics.MUTATION_APPLIED)
    with pytest.raises(ValueError):
        topics.topology_status(bad)
    with pytest.raises(ValueError):
        topics.decky(bad, topics.DECKY_STATE)
    with pytest.raises(ValueError):
        topics.system_health(bad)


def test_attacker_builder() -> None:
    assert topics.attacker(topics.ATTACKER_OBSERVED) == "attacker.observed"
    assert topics.attacker(topics.ATTACKER_SCORED) == "attacker.scored"
    assert topics.attacker(topics.ATTACKER_FINGERPRINTED) == "attacker.fingerprinted"
    # Dotted leaf is intentional — same as system.bus.health.
    assert topics.attacker(topics.ATTACKER_SESSION_STARTED) == "attacker.session.started"
    assert topics.attacker(topics.ATTACKER_SESSION_ENDED) == "attacker.session.ended"


def test_attacker_builder_rejects_empty() -> None:
    with pytest.raises(ValueError):
        topics.attacker("")


def test_system_health_builder() -> None:
    assert topics.system_health("sniffer") == "system.sniffer.health"
    assert topics.system_health("mutator") == "system.mutator.health"


def test_system_control_builder() -> None:
    assert topics.system_control("mutator") == "system.mutator.control"
    assert topics.system_control("collector") == "system.collector.control"


@pytest.mark.parametrize("bad", ["", "has.dot", "has*wildcard", "has>wild", "with space", "with\ttab"])
def test_system_control_rejects_bad_segments(bad: str) -> None:
    with pytest.raises(ValueError):
        topics.system_control(bad)
