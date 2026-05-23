# SPDX-License-Identifier: AGPL-3.0-or-later
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
from typing import Iterable

from decnet.topology.repository import TopologyRepository
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
        self._host_set: frozenset[str] = frozenset(str(h) for h in self._net.hosts())
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
        if ip not in self._host_set:
            raise ValueError(f"{ip} not in {self._net.with_prefixlen}")
        self._taken.add(ip)

    def release(self, ip: str) -> None:
        self._taken.discard(ip)

    def is_free(self, ip: str) -> bool:
        return ip not in self._taken and ip in self._host_set and ip != self._gateway


class SubnetAllocator:
    """Hands out ``/24`` subnets inside a parent network.

    Accepted ``base_prefix`` forms:

    * Full CIDR:  ``"172.16.0.0/12"`` → 4096 ``/24`` slots
    * Legacy two-octet shorthand: ``"172.20"`` → auto-lifted to
      ``"172.20.0.0/16"`` (256 slots), for backward compat with
      configs written before mass-scale topologies were a thing.

    The parent must be at most ``/24`` wide (i.e. its prefix length
    must be ≤ 24); a ``/24`` base yields exactly one slot, anything
    larger yields more.
    """

    def __init__(
        self,
        base_prefix: str,
        reserved: Iterable[str] = (),
    ) -> None:
        parent = _parse_base(base_prefix)
        if parent.prefixlen > 24:
            raise ValueError(
                f"subnet base {parent.with_prefixlen} is narrower than /24; "
                "cannot carve /24 children out of it"
            )
        self._parent = parent
        # A generator over all /24 subnets of the parent. ipaddress
        # yields them in order, so the allocator preserves the legacy
        # "sequential-third-octet" behaviour for /16 bases. For /12
        # bases you get second.third-octet sweep.
        self._iter = parent.subnets(new_prefix=24) if parent.prefixlen < 24 else iter([parent])
        self._reserved: set[str] = {s for s in reserved}

    def next_free(self) -> str:
        for net in self._iter:
            subnet = net.with_prefixlen
            if subnet not in self._reserved:
                self._reserved.add(subnet)
                return subnet
        raise AllocatorExhausted(
            f"no free /24s left under {self._parent.with_prefixlen}"
        )

    def reserve(self, subnet: str) -> None:
        self._reserved.add(subnet)

    def is_free(self, subnet: str) -> bool:
        return subnet not in self._reserved


def _parse_base(base_prefix: str) -> IPv4Network:
    """Accept either ``'a.b.c.d/n'`` or legacy ``'a.b'`` shorthand."""
    stripped = base_prefix.strip().rstrip(".")
    if "/" in stripped:
        return IPv4Network(stripped, strict=False)
    octets = stripped.split(".")
    if len(octets) == 2:
        return IPv4Network(f"{stripped}.0.0/16", strict=False)
    if len(octets) == 4:
        return IPv4Network(f"{stripped}/24", strict=False)
    raise ValueError(
        f"unrecognised subnet base {base_prefix!r}; expected 'x.y' or CIDR"
    )


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


async def reserved_subnets(repo: TopologyRepository) -> set[str]:
    """All LAN subnets currently claimed by non-torn-down topologies."""
    out: set[str] = set()
    for status in _SUBNET_CLAIMING_STATES:
        for topo in await repo.list_topologies(status=status):
            for lan in await repo.list_lans_for_topology(topo.id):
                if lan.subnet:
                    out.add(lan.subnet)
    return out
