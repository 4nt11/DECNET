"""Provider-agnostic country lookup.

A :class:`Lookup` is a frozen, sorted array of (start_ip, end_ip, cc)
ranges queried via :mod:`bisect`. O(log n) on ~200k ranges.

Private/loopback/invalid IPv4 and all IPv6 addresses resolve to
``None`` — honeypots hit plenty of RFC1918 traffic from our own probes,
and IPv6 country-mapping is explicitly out of MVP scope.
"""
from __future__ import annotations

import bisect
import ipaddress
import pickle  # nosec B403 — self-produced cache under /var/lib/decnet, never deserialized from untrusted input
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

Range = Tuple[int, int, str]


@dataclass
class Lookup:
    """Indexed country lookup over IPv4 ranges."""

    # Parallel arrays for bisect: _starts[i] is the start-IP of the i-th
    # range, _ends[i] its inclusive end, _ccs[i] its country code.
    _starts: List[int]
    _ends: List[int]
    _ccs: List[str]

    @classmethod
    def from_ranges(cls, ranges: Iterable[Range]) -> "Lookup":
        """Build a Lookup from (start, end_inclusive, cc) triples.

        Ranges are sorted by start; overlapping ranges are resolved
        last-writer-wins when both starts collide. Non-overlapping
        adjacency is preserved.
        """
        sorted_ranges = sorted(ranges, key=lambda r: (r[0], r[1]))
        starts: List[int] = []
        ends: List[int] = []
        ccs: List[str] = []
        for start, end, cc in sorted_ranges:
            if starts and starts[-1] == start:
                ends[-1] = end
                ccs[-1] = cc
                continue
            starts.append(start)
            ends.append(end)
            ccs.append(cc)
        return cls(starts, ends, ccs)

    def country(self, ip: str) -> Optional[str]:
        """Return the 2-letter ISO country code for ``ip`` or ``None``.

        ``None`` on: IPv6, private/loopback/link-local/multicast/reserved
        addresses, malformed strings, and IPs outside every known range.
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
        # bisect_right gives the first start > n; the candidate range is
        # the one immediately before it.
        idx = bisect.bisect_right(self._starts, n) - 1
        if idx < 0:
            return None
        if n <= self._ends[idx]:
            return self._ccs[idx]
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
                    "ccs": self._ccs,
                },
                fh,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> "Lookup":
        """Load a pickled lookup from *path*."""
        with path.open("rb") as fh:
            data = pickle.load(fh)  # nosec B301 — self-produced file under /var/lib/decnet
        if data.get("version") != 1:
            raise ValueError(f"unsupported lookup index version: {data.get('version')!r}")
        return cls(data["starts"], data["ends"], data["ccs"])


def iter_ranges(items: Iterable[Range]) -> Iterator[Range]:
    """Passthrough helper — kept so providers can compose iterators without
    importing private symbols."""
    yield from items
