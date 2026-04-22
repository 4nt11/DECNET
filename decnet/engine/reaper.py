"""Orphan Docker resource reaper for MazeNET topologies.

Every topology's Docker resources carry the fixed prefix
``decnet_t_<first-8-of-topology-uuid>_`` (see
:func:`decnet.topology.compose._network_name`). When a topology row is
deleted from the DB without a proper teardown — operator error, crashed
master, straight ``DELETE FROM topologies`` — the containers and
networks linger and steal IPAM pools.

This module walks the local Docker daemon, extracts the 8-char prefix
from every matching container/network, compares against the set of
prefixes that *do* map to a known topology, and removes the rest.

It never touches resources whose prefix matches a live topology, and it
never touches non-DECNET resources.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import docker

from decnet.logging import get_logger
from decnet.network import remove_bridge_network

log = get_logger("engine.reaper")

# decnet_t_<8hex>_<anything>. The 8-char prefix is sliced from the
# topology UUID in decnet.topology.compose._network_name. Tolerate any
# suffix (network name, decky name) after the second underscore.
_RESOURCE_NAME_RE = re.compile(r"^decnet_t_([0-9a-f]{8})_")


@dataclass
class ReapReport:
    """Outcome of a reap pass — what was found and what was removed."""

    live_prefixes: list[str] = field(default_factory=list)
    orphan_prefixes: list[str] = field(default_factory=list)
    containers_removed: list[str] = field(default_factory=list)
    networks_removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "live_prefixes": self.live_prefixes,
            "orphan_prefixes": self.orphan_prefixes,
            "containers_removed": self.containers_removed,
            "networks_removed": self.networks_removed,
            "errors": self.errors,
        }


def _prefix_of(name: str) -> Optional[str]:
    m = _RESOURCE_NAME_RE.match(name)
    return m.group(1) if m else None


async def _live_prefixes(repo: Any) -> set[str]:
    """Every topology-id prefix the DB still knows about.

    Tearing down only marks ``torn_down``; the row stays around for
    audit. We consider *every* persisted topology to be live for the
    reaper so we never race a concurrent teardown / redeploy by nuking
    its networks mid-flight. Operators who want those resources gone
    should delete the topology row (which cascades) or run teardown.
    """
    rows = await repo.list_topologies()
    return {r["id"][:8] for r in rows}


def _orphan_prefixes(
    container_names: Iterable[str],
    network_names: Iterable[str],
    live: set[str],
) -> tuple[set[str], list[str], list[str]]:
    """Return (orphan_prefixes, decnet_containers, decnet_networks).

    Pure function — no Docker / repo I/O. Kept separate so the test
    suite can drive it without mocking the docker SDK."""
    c_decnet = [n for n in container_names if _prefix_of(n) is not None]
    n_decnet = [n for n in network_names if _prefix_of(n) is not None]
    orphans = {
        _prefix_of(n) for n in (*c_decnet, *n_decnet)
    } - live
    orphans.discard(None)
    return orphans, c_decnet, n_decnet  # type: ignore[return-value]


async def reap_orphan_topology_resources(
    repo: Any,
    client: Optional[docker.DockerClient] = None,
) -> ReapReport:
    """Remove Docker containers + networks whose topology id is gone.

    * Enumerates every container and network whose name matches the
      DECNET topology pattern.
    * Computes the set of prefixes still referenced in the DB.
    * Force-removes every container (so networks can drop their
      endpoints), then removes the networks in a second pass.
    * Errors on any single resource are captured into the report but
      never abort the sweep — one stuck container should not block the
      other nineteen from being cleaned up.
    """
    if client is None:
        client = docker.from_env()

    live = await _live_prefixes(repo)
    report = ReapReport(live_prefixes=sorted(live))

    try:
        containers = client.containers.list(all=True)
        networks = client.networks.list()
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"docker list failed: {exc}")
        return report

    container_names = [c.name for c in containers]
    network_names = [n.name for n in networks]
    orphans, decnet_containers, decnet_networks = _orphan_prefixes(
        container_names, network_names, live
    )
    report.orphan_prefixes = sorted(orphans)

    if not orphans:
        log.info(
            "reaper: no orphans (decnet containers=%d, networks=%d, live=%d)",
            len(decnet_containers), len(decnet_networks), len(live),
        )
        return report

    # Pass 1: containers. Force-remove so we don't hang on a stopped
    # container whose network is about to be killed.
    for c in containers:
        prefix = _prefix_of(c.name)
        if prefix is None or prefix not in orphans:
            continue
        try:
            c.remove(force=True)
            report.containers_removed.append(c.name)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"container {c.name!r}: {exc}")
            log.warning("reaper: container %s remove failed: %s", c.name, exc)

    # Pass 2: networks.
    for n in networks:
        prefix = _prefix_of(n.name)
        if prefix is None or prefix not in orphans:
            continue
        try:
            remove_bridge_network(client, n.name)
            report.networks_removed.append(n.name)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"network {n.name!r}: {exc}")
            log.warning("reaper: network %s remove failed: %s", n.name, exc)

    log.info(
        "reaper: removed %d container(s), %d network(s) across %d orphan prefix(es)",
        len(report.containers_removed),
        len(report.networks_removed),
        len(report.orphan_prefixes),
    )
    return report


__all__ = [
    "ReapReport",
    "reap_orphan_topology_resources",
]
