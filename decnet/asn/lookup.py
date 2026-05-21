"""Provider-agnostic IP→ASN lookup.

A :class:`AsnLookup` is a frozen, sorted array of ``(start_ip,
end_ip_inclusive, AsnInfo)`` ranges queried via :mod:`bisect`.
O(log n) on ~600k ranges (a current iptoasn dump is ~580k rows).

Private/loopback/invalid IPv4 and all IPv6 addresses resolve to
``None`` — the same policy :mod:`decnet.geoip.lookup` uses.
"""
from __future__ import annotations

import bisect
import ipaddress
import pickle  # nosec B403 — self-produced cache under /var/lib/decnet, never deserialized from untrusted input
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class AsnInfo:
    """One BGP-announced prefix's origin metadata."""

    asn: int
    name: str  # AS description / org name; "" if absent in the source data
    prefix: Optional[str] = None  # synthesized covering CIDR; set at lookup time, not at rest


Range = Tuple[int, int, AsnInfo]


def _synthesize_prefix(start_int: int, end_int: int, queried_int: int) -> Optional[str]:
    """Return the most-specific CIDR from [start, end] that contains queried_int."""
    try:
        for net in ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start_int), ipaddress.IPv4Address(end_int)
        ):
            if queried_int >= int(net.network_address) and queried_int <= int(net.broadcast_address):
                return str(net)
    except (ValueError, TypeError):
        pass
    return None


@dataclass
class AsnLookup:
    """Indexed AS lookup over IPv4 ranges."""

    # Parallel arrays for bisect: _starts[i] is the start-IP of the i-th
    # range, _ends[i] its inclusive end, _infos[i] its AsnInfo.
    _starts: List[int]
    _ends: List[int]
    _infos: List[AsnInfo]

    @classmethod
    def from_ranges(cls, ranges: Iterable[Range]) -> "AsnLookup":
        """Build a lookup from ``(start, end_inclusive, AsnInfo)`` triples.

        Ranges are sorted by start; on identical starts, last writer
        wins (matches :class:`decnet.geoip.lookup.Lookup` semantics).
        Non-overlapping adjacency is preserved.
        """
        sorted_ranges = sorted(ranges, key=lambda r: (r[0], r[1]))
        starts: List[int] = []
        ends: List[int] = []
        infos: List[AsnInfo] = []
        for start, end, info in sorted_ranges:
            if starts and starts[-1] == start:
                ends[-1] = end
                infos[-1] = info
                continue
            starts.append(start)
            ends.append(end)
            infos.append(info)
        return cls(starts, ends, infos)

    def asn(self, ip: str) -> Optional[AsnInfo]:
        """Return the :class:`AsnInfo` for ``ip`` or ``None``.

        ``None`` on: IPv6, private/loopback/link-local/multicast/reserved
        addresses, malformed strings, and IPs outside every BGP-announced
        range in the source dump.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address):
            return None
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return None

        n = int(addr)
        idx = bisect.bisect_right(self._starts, n) - 1
        if idx < 0:
            return None
        if n <= self._ends[idx]:
            info = self._infos[idx]
            prefix = _synthesize_prefix(self._starts[idx], self._ends[idx], n)
            return AsnInfo(asn=info.asn, name=info.name, prefix=prefix)
        return None

    def __len__(self) -> int:
        return len(self._starts)

    # ---------- persistence ----------

    def save(self, path: Path) -> None:
        """Pickle the lookup to *path* (atomic rename)."""
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("wb") as fh:
            pickle.dump(
                {
                    "version": 1,
                    "starts": self._starts,
                    "ends": self._ends,
                    "infos": [(i.asn, i.name) for i in self._infos],
                },
                fh,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> "AsnLookup":
        """Load a pickled lookup from *path*."""
        with path.open("rb") as fh:
            data = pickle.load(fh)  # nosec B301 — self-produced file under /var/lib/decnet
        if data.get("version") != 1:
            raise ValueError(
                f"unsupported asn-lookup index version: {data.get('version')!r}"
            )
        infos = [AsnInfo(asn=a, name=n) for a, n in data["infos"]]
        return cls(data["starts"], data["ends"], infos)
