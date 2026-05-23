# SPDX-License-Identifier: AGPL-3.0-or-later
"""Parser tests for RIR delegated-stats files."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from decnet.geoip.rir.parse import parse_file


_FIXTURE = """\
2|ripencc|20260420|230000|19830101|20260419|+0000
ripencc|*|asn|*|35000|summary
ripencc|*|ipv4|*|25000|summary
ripencc|DE|ipv4|85.214.0.0|65536|20060814|allocated|abc
ripencc|GB|ipv4|46.101.0.0|65536|20120101|assigned|def
ripencc|FR|ipv6|2001:db8::|32|20100101|allocated|ghi
ripencc|*|ipv4|5.0.0.0|256|20200101|reserved|jkl
ripencc|ZZ|ipv4|6.0.0.0|256|20200101|allocated|mno
ripencc|ES|ipv4|*|0|20200101|allocated|pqr
# comment line
ripencc|IT|asn|12345|1|20100101|allocated|stu
arin|US|ipv4|8.8.8.0|256|20000101|allocated|xyz
"""


def test_parse_skips_non_ipv4_and_sentinels(tmp_path: Path) -> None:
    fixture = tmp_path / "ripe.txt"
    fixture.write_text(_FIXTURE)
    ranges = list(parse_file(fixture))
    ccs = {r[2] for r in ranges}
    # v4 allocated/assigned with real country codes only.
    assert ccs == {"DE", "GB", "US"}


def test_parse_range_boundaries(tmp_path: Path) -> None:
    fixture = tmp_path / "arin.txt"
    fixture.write_text(_FIXTURE)
    ranges = [r for r in parse_file(fixture) if r[2] == "US"]
    assert len(ranges) == 1
    start, end, cc = ranges[0]
    assert start == int(ipaddress.IPv4Address("8.8.8.0"))
    assert end == int(ipaddress.IPv4Address("8.8.8.255"))
    assert cc == "US"


def test_parse_lowercase_cc_is_uppercased(tmp_path: Path) -> None:
    fixture = tmp_path / "apnic.txt"
    fixture.write_text("apnic|jp|ipv4|1.0.0.0|256|19990101|allocated|abc\n")
    ranges = list(parse_file(fixture))
    assert ranges == [(int(ipaddress.IPv4Address("1.0.0.0")),
                       int(ipaddress.IPv4Address("1.0.0.255")),
                       "JP")]


def test_parse_malformed_lines_are_skipped(tmp_path: Path) -> None:
    fixture = tmp_path / "broken.txt"
    fixture.write_text(
        "garbage\n"
        "a|b|c\n"
        "ripencc|DE|ipv4|not-an-ip|65536|20060814|allocated|abc\n"
        "ripencc|DE|ipv4|85.214.0.0|not-a-count|20060814|allocated|abc\n"
        "ripencc|DE|ipv4|85.214.0.0|65536|20060814|allocated|ok\n"
    )
    ranges = list(parse_file(fixture))
    assert len(ranges) == 1
    assert ranges[0][2] == "DE"
