"""Parser for the iptoasn.com ``ip2asn-v4.tsv`` dump.

Line shape (gzipped, one row per BGP-announced prefix)::

    1.0.0.0\\t1.0.0.255\\t13335\\tUS\\tCLOUDFLARENET

Fields: ``range_start``, ``range_end``, ``as_number``, ``country_code``,
``as_description``. Both range columns are dotted IPv4 strings (the dump
is IPv4-only — there's a separate ``ip2asn-v6.tsv.gz`` we don't pull).

Rows skipped:

* ``as_number == 0`` — iptoasn's sentinel for "unannounced" / private
  / reserved space. Country may still be present (``"None"`` / two-letter
  CC) but we don't care: the geoip module owns country, ASN owns BGP.
* Rows where either range column won't parse as IPv4.
* Rows with fewer than 3 tab-separated columns.
"""
from __future__ import annotations

import gzip
import ipaddress
import logging
from pathlib import Path
from typing import Iterator

from decnet.asn.lookup import AsnInfo, Range

logger = logging.getLogger("decnet.asn.iptoasn.parse")


def parse_file(path: Path) -> Iterator[Range]:
    """Yield ``(start_int, end_int_inclusive, AsnInfo)`` for every BGP row.

    Accepts a gzipped path (``*.tsv.gz``); plain TSV is also fine for
    test harnesses that hand-craft small fixtures.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            start_s, end_s, asn_s = parts[0], parts[1], parts[2]
            # Description is the 5th column; iptoasn quotes nothing,
            # but the field can contain stray whitespace. ``""`` when
            # missing or unknown.
            name = parts[4].strip() if len(parts) >= 5 else ""

            try:
                asn = int(asn_s)
            except ValueError:
                logger.debug(
                    "asn.iptoasn: skipping malformed asn line %d in %s",
                    lineno, path.name,
                )
                continue
            # ASN 0 is iptoasn's sentinel for unannounced / sentinel
            # space. Skip — there's no useful enrichment to attach.
            if asn == 0:
                continue

            try:
                start_int = int(ipaddress.IPv4Address(start_s))
                end_int = int(ipaddress.IPv4Address(end_s))
            except (ValueError, ipaddress.AddressValueError):
                logger.debug(
                    "asn.iptoasn: skipping malformed addr line %d in %s",
                    lineno, path.name,
                )
                continue
            if end_int < start_int:
                continue

            yield (start_int, end_int, AsnInfo(asn=asn, name=name))
