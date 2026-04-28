"""Parser tests for the iptoasn TSV dump."""
from __future__ import annotations

import gzip
import ipaddress
from pathlib import Path

from decnet.asn.iptoasn.parse import parse_file


_FIXTURE_TSV = (
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n"
    # ASN 0 sentinel — must be skipped.
    "100.64.0.0\t100.127.255.255\t0\tNone\tNot routed\n"
    # Malformed addresses — skipped.
    "garbage\tnonsense\t12345\tXX\twhatever\n"
    # Reversed range (end < start) — skipped.
    "10.0.0.10\t10.0.0.5\t99999\tXX\tBackwards\n"
    # Valid row with empty description.
    "46.101.0.0\t46.101.255.255\t14061\tDE\t\n"
)


def test_parse_plain_tsv(tmp_path: Path) -> None:
    fixture = tmp_path / "ip2asn-v4.tsv"
    fixture.write_text(_FIXTURE_TSV)
    ranges = list(parse_file(fixture))
    asns = {r[2].asn for r in ranges}
    assert asns == {13335, 15169, 14061}


def test_parse_gzipped(tmp_path: Path) -> None:
    fixture = tmp_path / "ip2asn-v4.tsv.gz"
    with gzip.open(fixture, "wt", encoding="utf-8") as fh:
        fh.write(_FIXTURE_TSV)
    ranges = list(parse_file(fixture))
    asns = {r[2].asn for r in ranges}
    assert 13335 in asns and 15169 in asns


def test_parse_range_boundaries(tmp_path: Path) -> None:
    fixture = tmp_path / "ip2asn-v4.tsv"
    fixture.write_text(_FIXTURE_TSV)
    ranges = [r for r in parse_file(fixture) if r[2].asn == 15169]
    assert len(ranges) == 1
    start, end, info = ranges[0]
    assert start == int(ipaddress.IPv4Address("8.8.8.0"))
    assert end == int(ipaddress.IPv4Address("8.8.8.255"))
    assert info.name == "GOOGLE"


def test_parse_empty_description_kept(tmp_path: Path) -> None:
    fixture = tmp_path / "ip2asn-v4.tsv"
    fixture.write_text(_FIXTURE_TSV)
    ranges = [r for r in parse_file(fixture) if r[2].asn == 14061]
    assert ranges[0][2].name == ""
