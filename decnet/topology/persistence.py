"""Adapter between :class:`GeneratedTopology` and the repository layer."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Any

from decnet.topology.allocator import IPAllocator
from decnet.topology.config import GeneratedTopology
from decnet.topology.status import TopologyStatus, assert_transition


async def persist(repo: Any, plan: GeneratedTopology) -> str:
    """Write a generated plan to the repo as a ``pending`` topology.

    Returns the newly created topology id.  All child rows are written
    atomically relative to each other (SQLite transactions are per-call
    here; the repo methods each commit — good enough for initial create
    since the whole chain is invoked before any external side effects).
    """
    topology_id = await repo.create_topology(
        {
            "name": plan.config.name,
            "mode": plan.config.mode,
            "config_snapshot": plan.config.model_dump(),
        }
    )

    lan_ids: dict[str, str] = {}
    for lan in plan.lans:
        lan_id = await repo.add_lan(
            {
                "topology_id": topology_id,
                "name": lan.name,
                "subnet": lan.subnet,
                "is_dmz": lan.is_dmz,
                "x": lan.x,
                "y": lan.y,
            }
        )
        lan_ids[lan.name] = lan_id

    decky_ids: dict[str, str] = {}
    for decky in plan.deckies:
        # Primary IP: the first LAN the decky was assigned to (insertion
        # order of ips_by_lan, which reflects generator ordering —
        # home LAN first, then any bridge targets).
        primary_lan = next(iter(decky.ips_by_lan))
        primary_ip = decky.ips_by_lan[primary_lan]
        decky_uuid = await repo.add_topology_decky(
            {
                "topology_id": topology_id,
                "name": decky.name,
                "services": decky.services,
                "decky_config": {
                    "name": decky.name,
                    "services": decky.services,
                    "ips_by_lan": decky.ips_by_lan,
                    "forwards_l3": decky.forwards_l3,
                    "service_config": decky.service_config,
                },
                "ip": primary_ip,
                "x": decky.x,
                "y": decky.y,
            }
        )
        decky_ids[decky.name] = decky_uuid

    for edge in plan.edges:
        await repo.add_topology_edge(
            {
                "topology_id": topology_id,
                "decky_uuid": decky_ids[edge.decky_name],
                "lan_id": lan_ids[edge.lan_name],
                "is_bridge": edge.is_bridge,
                "forwards_l3": edge.forwards_l3,
            }
        )

    return topology_id


async def transition_status(
    repo: Any,
    topology_id: str,
    new_status: str,
    reason: str | None = None,
) -> None:
    """Legal-only status transition.

    Raises :class:`decnet.topology.status.TopologyStatusError` if the
    current status cannot legally transition to ``new_status``.
    """
    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise ValueError(f"topology {topology_id!r} not found")
    assert_transition(topo["status"], new_status)
    await repo.update_topology_status(topology_id, new_status, reason=reason)


async def hydrate(repo: Any, topology_id: str) -> dict[str, Any] | None:
    """Load a topology + children into a single dict for callers.

    Shape::

        {
            "topology": { ...row... },
            "lans": [ {...}, ... ],
            "deckies": [ {...}, ... ],
            "edges": [ {...}, ... ],
        }

    Returns ``None`` if the topology does not exist.
    """
    topo = await repo.get_topology(topology_id)
    if topo is None:
        return None
    lans = await repo.list_lans_for_topology(topology_id)
    deckies = await repo.list_topology_deckies(topology_id)
    edges = await repo.list_topology_edges(topology_id)
    _backfill_decky_configs(lans, deckies, edges)
    return {
        "topology": topo,
        "lans": lans,
        "deckies": deckies,
        "edges": edges,
    }


def _backfill_decky_configs(
    lans: list[dict[str, Any]],
    deckies: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    """Fill in ``decky_config['name']`` and ``ips_by_lan`` for UI-created rows.

    The generator path writes these fields at persist-time; the REST
    CRUD path writes whatever the client sends (often just archetype
    flags).  Compose generation requires both, so we normalise here so
    every write path feeds the same shape downstream.
    """
    lans_by_id = {lan["id"]: lan for lan in lans}
    allocators: dict[str, IPAllocator] = {}

    def _alloc(lan_id: str) -> IPAllocator | None:
        lan = lans_by_id.get(lan_id)
        if lan is None or not lan.get("subnet"):
            return None
        if lan_id not in allocators:
            allocators[lan_id] = IPAllocator(lan["subnet"])
        return allocators[lan_id]

    decky_edges: dict[str, list[str]] = {}
    for e in edges:
        decky_edges.setdefault(e["decky_uuid"], []).append(e["lan_id"])

    ordered = sorted(deckies, key=lambda d: (d.get("name", ""), d["uuid"]))

    # Pass 1: reserve IPs already declared in decky_config.
    for decky in ordered:
        cfg = decky.get("decky_config") or {}
        existing = cfg.get("ips_by_lan") or {}
        for lan_id in decky_edges.get(decky["uuid"], []):
            lan = lans_by_id.get(lan_id)
            if lan is None:
                continue
            alloc = _alloc(lan_id)
            if alloc is None:
                continue
            ip = existing.get(lan["name"])
            if ip and alloc.is_free(ip):
                alloc.reserve(ip)

    # Pass 2: fill gaps; rewrite decky_config.
    for decky in ordered:
        cfg = dict(decky.get("decky_config") or {})
        cfg.setdefault("name", decky.get("name"))
        ips_by_lan: dict[str, str] = dict(cfg.get("ips_by_lan") or {})
        primary_ip = decky.get("ip")
        for lan_id in decky_edges.get(decky["uuid"], []):
            lan = lans_by_id.get(lan_id)
            if lan is None:
                continue
            if lan["name"] in ips_by_lan:
                continue
            alloc = _alloc(lan_id)
            if alloc is None:
                continue
            ip: str | None = None
            if primary_ip:
                try:
                    if (
                        IPv4Address(primary_ip) in IPv4Network(lan["subnet"])
                        and alloc.is_free(primary_ip)
                    ):
                        ip = primary_ip
                        alloc.reserve(ip)
                except (ValueError, TypeError):
                    pass
            if ip is None:
                ip = alloc.next_free()
            ips_by_lan[lan["name"]] = ip
        cfg["ips_by_lan"] = ips_by_lan
        decky["decky_config"] = cfg


# Re-export the status constants so callers can ``from decnet.topology.persistence
# import TopologyStatus`` without chasing modules.
__all__ = ["persist", "transition_status", "hydrate", "TopologyStatus"]
