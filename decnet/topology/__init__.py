# SPDX-License-Identifier: AGPL-3.0-or-later
"""MazeNET — nested deception topologies.

A topology is an arbitrary-depth DAG of LANs, connected by multi-homed
"bridge deckies" that optionally forward L3 between segments.  One LAN
is marked as the DMZ (Internet-facing).  Persisted via the repo pattern;
deployed via :mod:`decnet.engine.deployer`.
"""
from decnet.topology.config import TopologyConfig, GeneratedTopology
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


def __getattr__(name: str):
    # ponytail: lazy re-export — `generate` pulls generator→allocator→repository→the
    # full SQLModel ORM (~38MB). Defer it so importing this package (which every worker
    # does transitively via the CLI) doesn't drag the DB layer into DB-less workers.
    if name == "generate":
        from decnet.topology.generator import generate

        return generate
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
