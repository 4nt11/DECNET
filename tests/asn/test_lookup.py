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
