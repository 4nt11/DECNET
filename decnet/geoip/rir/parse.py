"""Parser for RIR ``delegated-*-extended`` files.

Line shape (the bits we care about)::

    ripencc|DE|ipv4|85.214.0.0|65536|20060814|allocated|<opaque-id>

Fields: registry, country, type (ipv4/ipv6/asn), start, count, date,
status, id. We emit one ``(start_int, end_int_inclusive, country)``
tuple per ``ipv4|<cc>|...|allocated|assigned`` row.

Rows skipped:

* ``ipv6`` and ``asn`` types — IPv6 is out of MVP scope, ASN is a
  different table.
* ``summary`` / ``version`` header lines (registry|*|*|*|*|summary).
* Rows with status ``reserved`` / ``available`` — no country assigned.
* Rows with country ``*`` or ``ZZ`` — sentinel for unassigned space.
* Rows where count is not a valid power-of-two-ish positive integer
  (the RIR files are usually tidy, but defensive).
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Iterator, Tuple

Range = Tuple[int, int, str]

logger = logging.getLogger("decnet.geoip.rir.parse")

_VALID_STATUSES = frozenset({"allocated", "assigned"})
_SENTINEL_CCS = frozenset({"*", "ZZ", ""})


def parse_file(path: Path) -> Iterator[Range]:
    """Yield ``(start_int, end_int_inclusive, cc)`` for every ipv4 row."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 7:
                continue
            _registry, cc, rtype, start, count, _date, status = parts[:7]

            if rtype != "ipv4":
                continue
            if status not in _VALID_STATUSES:
                continue
            if cc in _SENTINEL_CCS:
                continue
            # summary header carries type=ipv4 but start=='*' and status
                # =='summary' — already filtered by _VALID_STATUSES, but
                # keep the guard for defensiveness.
            if start in ("*", ""):
                continue

            try:
                start_int = int(ipaddress.IPv4Address(start))
                n = int(count)
            except (ValueError, ipaddress.AddressValueError):
                logger.debug("geoip.rir: skipping malformed line %d in %s", lineno, path.name)
                continue
            if n <= 0:
                continue

            end_int = start_int + n - 1
            yield (start_int, end_int, cc.upper())
