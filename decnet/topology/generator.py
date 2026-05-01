"""MazeNET topology generator.

Produces a :class:`GeneratedTopology` — an in-memory DAG of LANs and
multi-homed deckies.  Deterministic under ``config.seed``: the same seed
always yields the same structure, service assignments, and IP layout.

The generator only plans the structure.  Persisting UUIDs to the repo
is :mod:`decnet.topology.persistence`; spawning Docker networks and
containers is :mod:`decnet.engine.deployer`.
"""
from __future__ import annotations

import random
from typing import Optional

from decnet.fleet import all_service_names
from decnet.topology.allocator import IPAllocator, SubnetAllocator
from decnet.topology.config import (
    GeneratedTopology,
    TopologyConfig,
    _PlannedDecky,
    _PlannedEdge,
    _PlannedLAN,
)

# Per-decky service count bounds. 1 minimum keeps every decky functional;
# 3 maximum balances service diversity against subnet IP utilization — the
# full non-singleton service pool (~28 entries) makes higher counts wasteful.
_SVC_MIN = 1
_SVC_MAX = 3


def _plan_lans(
    config: TopologyConfig,
    rng: random.Random,
    subnets: SubnetAllocator,
) -> list[_PlannedLAN]:
    """Plan LANs as a tree of depth ``config.depth``.

    Each non-leaf level adds [1, branching_factor] children per parent.
    LAN names and subnets are assigned in BFS order; subnets come from
    ``subnets``, which the caller may have pre-seeded with reservations
    from other topologies.
    """
    lans: list[_PlannedLAN] = []

    # DMZ root.
    lans.append(
        _PlannedLAN(
            name="LAN-00", subnet=subnets.next_free(), is_dmz=True, parent=None
        )
    )
    frontier: list[_PlannedLAN] = [lans[0]]

    for _level in range(1, config.depth + 1):
        next_frontier: list[_PlannedLAN] = []
        for parent in frontier:
            n_children = rng.randint(1, config.branching_factor)  # nosec B311
            for _ in range(n_children):
                idx = len(lans)
                child = _PlannedLAN(
                    name=f"LAN-{idx:02d}",
                    subnet=subnets.next_free(),
                    is_dmz=False,
                    parent=parent.name,
                )
                lans.append(child)
                next_frontier.append(child)
        frontier = next_frontier
        if not frontier:
            break
    return lans


def _pick_services(
    rng: random.Random,
    services_explicit: Optional[list[str]],
    pool: list[str],
    seen_service_pairs: set[frozenset],
) -> list[str]:
    if services_explicit:
        return list(services_explicit)
    if not pool:
        return []
    attempts = 0
    while True:
        count = rng.randint(_SVC_MIN, min(_SVC_MAX, len(pool)))  # nosec B311
        chosen = frozenset(rng.sample(pool, count))  # nosec B311
        attempts += 1
        if chosen not in seen_service_pairs or attempts > 20:
            break
    seen_service_pairs.add(chosen)
    return list(chosen)


def _take_ip(ip_allocs: dict[str, IPAllocator], lan_name: str) -> str:
    return ip_allocs[lan_name].next_free()


def _new_decky(
    home_lan: str,
    *,
    counter: list[int],
    rng: random.Random,
    config: TopologyConfig,
    svc_pool: list[str],
    seen_service_pairs: set[frozenset],
    ip_allocs: dict[str, IPAllocator],
    deckies: list[_PlannedDecky],
) -> _PlannedDecky:
    counter[0] += 1
    name = f"decky-{counter[0]:03d}"
    services = _pick_services(rng, config.services_explicit, svc_pool, seen_service_pairs)
    decky = _PlannedDecky(
        name=name,
        services=services,
        ips_by_lan={home_lan: _take_ip(ip_allocs, home_lan)},
    )
    deckies.append(decky)
    return decky


def generate(
    config: TopologyConfig,
    *,
    reserved_subnets: Optional[set[str]] = None,
) -> GeneratedTopology:
    """Generate a topology plan deterministically under ``config.seed``.

    The caller is responsible for persisting the plan via
    :mod:`decnet.topology.persistence` and then deploying it.

    ``reserved_subnets`` (optional): /24s already claimed by other
    topologies.  The subnet allocator skips these so two concurrent
    drafts can't collide.  Populate via
    :func:`decnet.topology.allocator.reserved_subnets`.
    """
    rng = random.Random(config.seed)  # nosec B311
    svc_pool = all_service_names() if config.randomize_services else []
    # Tracks unique service frozensets assigned so far; prevents every decky
    # from getting the same randomly-picked combo on small service pools.
    seen_service_pairs: set[frozenset] = set()

    subnets = SubnetAllocator(
        config.subnet_base_prefix, reserved=reserved_subnets or set()
    )
    lans = _plan_lans(config, rng, subnets)
    lans_by_name = {lan.name: lan for lan in lans}

    # Per-LAN IP allocators for deterministic assignment.
    ip_allocs: dict[str, IPAllocator] = {
        lan.name: IPAllocator(lan.subnet) for lan in lans
    }

    deckies: list[_PlannedDecky] = []
    edges: list[_PlannedEdge] = []
    decky_counter = [0]

    # Populate each LAN with its own deckies.
    for lan in lans:
        if lan.is_dmz:
            count = 1  # single DMZ decky (deaddeck)
        else:
            count = rng.randint(  # nosec B311
                config.deckies_per_lan_min, config.deckies_per_lan_max
            )
            if count < 1:
                count = 1  # every LAN needs ≥1 decky to host the bridge
        for _ in range(count):
            decky = _new_decky(
                lan.name,
                counter=decky_counter,
                rng=rng,
                config=config,
                svc_pool=svc_pool,
                seen_service_pairs=seen_service_pairs,
                ip_allocs=ip_allocs,
                deckies=deckies,
            )
            edges.append(
                _PlannedEdge(
                    decky_name=decky.name,
                    lan_name=lan.name,
                    is_bridge=False,
                    forwards_l3=False,
                )
            )

    # Parent↔child bridges.  For every non-DMZ LAN, pick one of its
    # deckies and multi-home it to the parent LAN.  This decky becomes
    # the bridge between the two segments.
    deckies_by_lan: dict[str, list[_PlannedDecky]] = {lan.name: [] for lan in lans}
    for e in edges:
        deckies_by_lan[e.lan_name].append(
            next(d for d in deckies if d.name == e.decky_name)
        )

    for lan in lans:
        if lan.is_dmz or lan.parent is None:
            continue
        candidates = deckies_by_lan[lan.name]
        bridge = rng.choice(candidates)  # nosec B311
        bridge.ips_by_lan[lan.parent] = _take_ip(ip_allocs, lan.parent)
        forwards = rng.random() < config.bridge_forward_probability  # nosec B311
        bridge.forwards_l3 = bridge.forwards_l3 or forwards
        # Mark both existing edges as bridge edges for this decky, and
        # add a new edge connecting it to the parent LAN.
        for e in edges:
            if e.decky_name == bridge.name:
                e.is_bridge = True
                e.forwards_l3 = bridge.forwards_l3
        edges.append(
            _PlannedEdge(
                decky_name=bridge.name,
                lan_name=lan.parent,
                is_bridge=True,
                forwards_l3=bridge.forwards_l3,
            )
        )

    # Cross-edges: with probability p, pick a non-parent, non-child,
    # non-self LAN and attach a random decky to it too.  Turns the tree
    # into a DAG.  Only rolls on non-DMZ LANs with ≥1 candidate peer.
    if config.cross_edge_probability > 0:
        for lan in lans:
            if lan.is_dmz:
                continue
            if rng.random() >= config.cross_edge_probability:  # nosec B311
                continue
            forbidden = {lan.name, lan.parent}
            forbidden |= {c.name for c in lans if c.parent == lan.name}
            peers = [p for p in lans if p.name not in forbidden]
            if not peers:
                continue
            peer = rng.choice(peers)  # nosec B311
            decky = rng.choice(deckies_by_lan[lan.name])  # nosec B311
            if peer.name in decky.ips_by_lan:
                continue  # already connected, skip
            decky.ips_by_lan[peer.name] = _take_ip(ip_allocs, peer.name)
            forwards = rng.random() < config.bridge_forward_probability  # nosec B311
            decky.forwards_l3 = decky.forwards_l3 or forwards
            for e in edges:
                if e.decky_name == decky.name:
                    e.is_bridge = True
                    e.forwards_l3 = decky.forwards_l3
            edges.append(
                _PlannedEdge(
                    decky_name=decky.name,
                    lan_name=peer.name,
                    is_bridge=True,
                    forwards_l3=decky.forwards_l3,
                )
            )

    del lans_by_name  # intermediate lookup, drop before returning

    return GeneratedTopology(
        config=config, lans=lans, deckies=deckies, edges=edges
    )
