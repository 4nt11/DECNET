"""MazeNET — nested deception topologies.

A topology is an arbitrary-depth DAG of LANs, connected by multi-homed
"bridge deckies" that optionally forward L3 between segments.  One LAN
is marked as the DMZ (Internet-facing).  Persisted via the repo pattern;
deployed via :mod:`decnet.engine.deployer`.
"""
from decnet.topology.config import TopologyConfig, GeneratedTopology
from decnet.topology.generator import generate
from decnet.topology.status import (
    TopologyStatus,
    assert_transition,
    TopologyStatusError,
)

__all__ = [
    "TopologyConfig",
    "GeneratedTopology",
    "generate",
    "TopologyStatus",
    "assert_transition",
    "TopologyStatusError",
]
