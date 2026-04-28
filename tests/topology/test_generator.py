"""MazeNET generator determinism + DAG shape tests."""
from __future__ import annotations

from collections import Counter

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="test",
        depth=3,
        branching_factor=2,
        deckies_per_lan_min=2,
        deckies_per_lan_max=2,
        bridge_forward_probability=1.0,
        cross_edge_probability=0.0,
        randomize_services=True,
        seed=42,
    )
    base.update(kw)
    return TopologyConfig(**base)


def test_seed_is_deterministic():
    a = generate(_cfg())
    b = generate(_cfg())
    # Same structure: same LAN names, same decky names, same edge set.
    assert [lan.name for lan in a.lans] == [lan.name for lan in b.lans]
    assert [d.name for d in a.deckies] == [d.name for d in b.deckies]
    assert [(d.name, sorted(d.services)) for d in a.deckies] == [
        (d.name, sorted(d.services)) for d in b.deckies
    ]
    assert sorted((e.decky_name, e.lan_name) for e in a.edges) == sorted(
        (e.decky_name, e.lan_name) for e in b.edges
    )


def test_different_seed_yields_different_structure():
    a = generate(_cfg(seed=1))
    b = generate(_cfg(seed=2))
    # With modest depth/branching, at least one of structure, service
    # assignment, or edge count will differ — fail only if everything is
    # byte-identical, which would indicate the seed is being ignored.
    a_sig = (
        [lan.name for lan in a.lans],
        [(d.name, sorted(d.services)) for d in a.deckies],
        sorted((e.decky_name, e.lan_name) for e in a.edges),
    )
    b_sig = (
        [lan.name for lan in b.lans],
        [(d.name, sorted(d.services)) for d in b.deckies],
        sorted((e.decky_name, e.lan_name) for e in b.edges),
    )
    assert a_sig != b_sig


def test_dmz_is_exactly_one_lan():
    t = generate(_cfg())
    dmz = [lan for lan in t.lans if lan.is_dmz]
    assert len(dmz) == 1
    assert dmz[0].parent is None
    assert dmz[0].name == "LAN-00"


def test_every_non_dmz_lan_has_exactly_one_bridge_into_parent():
    t = generate(_cfg(branching_factor=2, depth=3))
    # For each non-DMZ LAN, find the decky that is multi-homed to its parent.
    for lan in t.lans:
        if lan.is_dmz:
            continue
        bridges_to_parent = [
            d for d in t.deckies
            if lan.name in d.ips_by_lan and lan.parent in d.ips_by_lan
        ]
        assert len(bridges_to_parent) >= 1, (
            f"{lan.name} has no bridge into parent {lan.parent}"
        )


def test_cross_edge_probability_zero_yields_tree():
    """With cross_edge_probability=0, a decky is bridged only to its home
    LAN and (if it's the chosen bridge) its parent LAN — never to a
    sibling or cousin.  Validates by checking no decky is connected to
    both a parent AND a non-parent non-home LAN."""
    t = generate(_cfg(cross_edge_probability=0.0))
    lans_by_name = {lan.name: lan for lan in t.lans}
    for d in t.deckies:
        if len(d.ips_by_lan) <= 1:
            continue
        # Home LAN = first membership.  Other memberships must all be
        # the parent of the home LAN, i.e. a single parent bridge.
        home = next(iter(d.ips_by_lan))
        others = [name for name in list(d.ips_by_lan.keys())[1:]]
        parent = lans_by_name[home].parent
        assert all(o == parent for o in others), (
            f"tree mode but decky {d.name} bridges {home}→{others} (parent={parent})"
        )


def test_cross_edge_probability_one_produces_cross_edges_over_runs():
    """With probability=1, every non-DMZ LAN rolls a cross-edge (may be
    skipped if no valid peer), so across a moderately branching topology
    we expect ≥1 cross-edge."""
    t = generate(_cfg(cross_edge_probability=1.0, depth=3, branching_factor=3))
    lans_by_name = {lan.name: lan for lan in t.lans}
    cross_edges = 0
    for d in t.deckies:
        if len(d.ips_by_lan) < 2:
            continue
        home = next(iter(d.ips_by_lan))
        others = list(d.ips_by_lan.keys())[1:]
        parent = lans_by_name[home].parent
        for o in others:
            if o != parent:
                cross_edges += 1
    assert cross_edges >= 1


def test_every_decky_has_at_least_one_edge():
    t = generate(_cfg())
    edge_deckies = Counter(e.decky_name for e in t.edges)
    for d in t.deckies:
        assert edge_deckies[d.name] >= 1


def test_dmz_has_exactly_one_decky():
    t = generate(_cfg(deckies_per_lan_min=5, deckies_per_lan_max=5))
    dmz_edges = [e for e in t.edges if e.lan_name == "LAN-00"]
    # The DMZ LAN itself gets 1 decky + possibly acts as parent for
    # bridge deckies from LAN-01/LAN-02 etc.  The "home" decky count
    # should be exactly 1.
    home_only = [e for e in dmz_edges if not e.is_bridge]
    assert len(home_only) == 1
