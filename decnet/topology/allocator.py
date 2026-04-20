"""IP and subnet allocators for MazeNET topologies.

Extracted from :mod:`decnet.topology.generator` so the same primitives
can be reused by the generator, the pre-deploy editor (REST), and the
mutator reconciler.  The allocators are pure — persistence lives in the
repo; these objects hold in-memory state for a single planning pass.

``reserved_subnets`` queries the repo for every subnet currently claimed
by a non-``torn_down`` topology so a new draft cannot collide with an
open one.
"""
from __future__ import annotations

from ipaddress import IPv4Network
from typing import Any, Iterable

from decnet.topology.status import TopologyStatus


class AllocatorExhausted(RuntimeError):
    """Raised when an allocator cannot produce another value."""


class IPAllocator:
    """Hands out host IPs within a single LAN subnet.

    Skips the ``.1`` gateway.  Callers may pre-seed taken IPs via
    :meth:`reserve` before requesting :meth:`next_free`.
    """

    def __init__(self, subnet: str) -> None:
        self._net = IPv4Network(subnet, strict=False)
        self._gateway = str(next(self._net.hosts()))
        self._pool: list[str] = [
            str(ip) for ip in self._net.hosts() if str(ip) != self._gateway
        ]
        self._taken: set[str] = set()
        self._cursor = 0

    def next_free(self) -> str:
        while self._cursor < len(self._pool):
            ip = self._pool[self._cursor]
            self._cursor += 1
            if ip not in self._taken:
                self._taken.add(ip)
                return ip
        # Cursor past the end — fall back to a linear scan in case
        # releases opened up earlier slots.
        for ip in self._pool:
            if ip not in self._taken:
                self._taken.add(ip)
                return ip
        raise AllocatorExhausted(
            f"no free IPs left in {self._net.with_prefixlen}"
        )

    def reserve(self, ip: str) -> None:
        if ip == self._gateway:
            raise ValueError(f"{ip} is the gateway of {self._net.with_prefixlen}")
        if ip not in {str(h) for h in self._net.hosts()}:
            raise ValueError(f"{ip} not in {self._net.with_prefixlen}")
        self._taken.add(ip)

    def release(self, ip: str) -> None:
        self._taken.discard(ip)

    def is_free(self, ip: str) -> bool:
        return ip not in self._taken and ip in {str(h) for h in self._net.hosts()} and ip != self._gateway


class SubnetAllocator:
    """Hands out ``/24`` subnets under a base prefix (e.g. ``172.20``)."""

    _MAX_INDEX = 256  # 172.20.0/24 .. 172.20.255/24

    def __init__(
        self,
        base_prefix: str,
        reserved: Iterable[str] = (),
    ) -> None:
        self._base = base_prefix.rstrip(".")
        self._reserved: set[str] = {s for s in reserved}
        self._cursor = 0

    def _candidate(self, idx: int) -> str:
        return f"{self._base}.{idx}.0/24"

    def next_free(self) -> str:
        while self._cursor < self._MAX_INDEX:
            subnet = self._candidate(self._cursor)
            self._cursor += 1
            if subnet not in self._reserved:
                self._reserved.add(subnet)
                return subnet
        raise AllocatorExhausted(
            f"no free /24s left under {self._base}.0.0/16"
        )

    def reserve(self, subnet: str) -> None:
        self._reserved.add(subnet)

    def is_free(self, subnet: str) -> bool:
        return subnet not in self._reserved


# Topology statuses whose LANs still claim subnets.  torn_down is the
# only state that releases its networks back to the pool.
_SUBNET_CLAIMING_STATES: frozenset[str] = frozenset(
    {
        TopologyStatus.PENDING,
        TopologyStatus.DEPLOYING,
        TopologyStatus.ACTIVE,
        TopologyStatus.DEGRADED,
        TopologyStatus.FAILED,
        TopologyStatus.TEARING_DOWN,
    }
)


async def reserved_subnets(repo: Any) -> set[str]:
    """All LAN subnets currently claimed by non-torn-down topologies."""
    out: set[str] = set()
    for status in _SUBNET_CLAIMING_STATES:
        for topo in await repo.list_topologies(status=status):
            for lan in await repo.list_lans_for_topology(topo["id"]):
                subnet = lan.get("subnet")
                if subnet:
                    out.add(subnet)
    return out
