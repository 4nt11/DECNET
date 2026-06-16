# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lookup index tests."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from decnet.geoip.lookup import Lookup


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def _fixture_lookup() -> Lookup:
    return Lookup.from_ranges([
        (_ip("8.8.8.0"),    _ip("8.8.8.255"),   "US"),
        (_ip("85.214.0.0"), _ip("85.214.255.255"), "DE"),
        (_ip("46.101.0.0"), _ip("46.101.255.255"), "GB"),
    ])


def test_country_hits_known_ranges() -> None:
    lookup = _fixture_lookup()
    assert lookup.country("8.8.8.8") == "US"
    assert lookup.country("85.214.128.1") == "DE"
    assert lookup.country("46.101.10.20") == "GB"


def test_country_misses_gap() -> None:
    lookup = _fixture_lookup()
    # 9.0.0.0 sits between our fixtures — not in any range.
    assert lookup.country("9.0.0.0") is None


def test_country_private_loopback_returns_none() -> None:
    lookup = _fixture_lookup()
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "0.0.0.0"):
        assert lookup.country(ip) is None, ip


def test_country_ipv6_returns_none() -> None:
    lookup = _fixture_lookup()
    assert lookup.country("2001:db8::1") is None
    assert lookup.country("::1") is None


def test_country_invalid_returns_none() -> None:
    lookup = _fixture_lookup()
    assert lookup.country("not-an-ip") is None
    assert lookup.country("") is None
    assert lookup.country("999.1.1.1") is None


def test_lookup_roundtrips_through_pickle(tmp_path: Path) -> None:
    lookup = _fixture_lookup()
    cache = tmp_path / "idx.pkl"
    lookup.save(cache)
    loaded = Lookup.load(cache)
    assert len(loaded) == len(lookup)
    assert loaded.country("8.8.8.8") == "US"


def test_from_ranges_last_writer_wins_on_collision() -> None:
    lookup = Lookup.from_ranges([
        (_ip("1.0.0.0"), _ip("1.0.0.255"), "AU"),
        (_ip("1.0.0.0"), _ip("1.0.0.255"), "CN"),
    ])
    # Sorted by (start, end); last wins.
    assert lookup.country("1.0.0.5") == "CN"


def test_boundary_inclusive() -> None:
    lookup = _fixture_lookup()
    assert lookup.country("8.8.8.0") == "US"
    assert lookup.country("8.8.8.255") == "US"
    assert lookup.country("8.8.9.0") is None
