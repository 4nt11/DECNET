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
