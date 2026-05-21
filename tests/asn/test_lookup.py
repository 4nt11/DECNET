"""AsnLookup index tests."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from decnet.asn.lookup import AsnInfo, AsnLookup


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def _fixture_lookup() -> AsnLookup:
    return AsnLookup.from_ranges([
        (_ip("8.8.8.0"),    _ip("8.8.8.255"),     AsnInfo(15169, "GOOGLE")),
        (_ip("1.0.0.0"),    _ip("1.0.0.255"),     AsnInfo(13335, "CLOUDFLARENET")),
        (_ip("46.101.0.0"), _ip("46.101.255.255"), AsnInfo(14061, "DIGITALOCEAN")),
    ])


def test_asn_hits_known_ranges() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("8.8.8.8").asn == 15169
    assert lookup.asn("1.0.0.5").name == "CLOUDFLARENET"
    assert lookup.asn("46.101.10.20").asn == 14061


def test_prefix_aligned_range() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("8.8.8.8").prefix == "8.8.8.0/24"
    assert lookup.asn("8.8.8.0").prefix == "8.8.8.0/24"
    assert lookup.asn("8.8.8.255").prefix == "8.8.8.0/24"


def test_prefix_aligned_16() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("46.101.10.20").prefix == "46.101.0.0/16"


def test_prefix_non_power_of_two_range() -> None:
    # 1.0.0.0–1.0.0.191 spans /25 (0-127) and /26 (128-191)
    lookup = AsnLookup.from_ranges([
        (_ip("1.0.0.0"), _ip("1.0.0.191"), AsnInfo(13335, "CF")),
    ])
    assert lookup.asn("1.0.0.5").prefix == "1.0.0.0/25"
    assert lookup.asn("1.0.0.130").prefix == "1.0.0.128/26"


def test_prefix_single_host_range() -> None:
    lookup = AsnLookup.from_ranges([
        (_ip("1.2.3.4"), _ip("1.2.3.4"), AsnInfo(1, "X")),
    ])
    assert lookup.asn("1.2.3.4").prefix == "1.2.3.4/32"


def test_prefix_not_set_on_miss() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("9.0.0.0") is None


def test_asn_misses_gap() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("9.0.0.0") is None


def test_asn_private_returns_none() -> None:
    lookup = _fixture_lookup()
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "0.0.0.0"):
        assert lookup.asn(ip) is None, ip


def test_asn_ipv6_returns_none() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("2001:db8::1") is None
    assert lookup.asn("::1") is None


def test_asn_invalid_returns_none() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("not-an-ip") is None
    assert lookup.asn("") is None


def test_lookup_roundtrips_through_pickle(tmp_path: Path) -> None:
    lookup = _fixture_lookup()
    cache = tmp_path / "idx.pkl"
    lookup.save(cache)
    loaded = AsnLookup.load(cache)
    assert len(loaded) == len(lookup)
    assert loaded.asn("8.8.8.8").asn == 15169
    assert loaded.asn("8.8.8.8").name == "GOOGLE"


def test_from_ranges_last_writer_wins_on_collision() -> None:
    lookup = AsnLookup.from_ranges([
        (_ip("1.0.0.0"), _ip("1.0.0.255"), AsnInfo(1, "first")),
        (_ip("1.0.0.0"), _ip("1.0.0.255"), AsnInfo(2, "second")),
    ])
    assert lookup.asn("1.0.0.5").asn == 2


def test_boundary_inclusive() -> None:
    lookup = _fixture_lookup()
    assert lookup.asn("8.8.8.0").asn == 15169
    assert lookup.asn("8.8.8.255").asn == 15169
    assert lookup.asn("8.8.9.0") is None
