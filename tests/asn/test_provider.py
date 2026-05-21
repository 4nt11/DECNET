"""IptoasnProvider + factory + public API tests."""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest


def _seed_fixture(root: Path, content: str = "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n") -> None:
    target = root / "ip2asn-v4.tsv.gz"
    with gzip.open(target, "wt", encoding="utf-8") as fh:
        fh.write(content)


def test_factory_returns_iptoasn_by_default() -> None:
    from decnet.asn.factory import get_provider

    provider = get_provider()
    assert provider.name == "iptoasn"


def test_factory_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from decnet.asn import factory

    monkeypatch.setenv("DECNET_ASN_PROVIDER", "nope")
    factory.reset_cache()
    with pytest.raises(ValueError):
        factory.get_provider()


def test_provider_build_lookup_empty_when_no_files(tmp_path: Path) -> None:
    from decnet.asn.iptoasn.provider import IptoasnProvider

    p = IptoasnProvider()
    lookup = p.build_lookup()
    assert len(lookup) == 0
    assert lookup.asn("8.8.8.8") is None


def test_provider_build_lookup_reads_present_file(tmp_path: Path) -> None:
    from decnet.asn.iptoasn.provider import IptoasnProvider

    _seed_fixture(tmp_path)
    p = IptoasnProvider()
    lookup = p.build_lookup()
    info = lookup.asn("8.8.8.8")
    assert info is not None
    assert info.asn == 15169
    assert info.name == "GOOGLE"


def test_provider_uses_cache_when_fresh(tmp_path: Path) -> None:
    from decnet.asn.iptoasn.provider import IptoasnProvider

    _seed_fixture(tmp_path)
    p = IptoasnProvider()
    a = p.build_lookup()
    assert (tmp_path / ".iptoasn_index.pkl").exists()

    p2 = IptoasnProvider()
    b = p2.build_lookup()
    assert len(b) == len(a)


def test_enrich_ip_short_circuits_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    import decnet.asn as asn

    monkeypatch.setenv("DECNET_ASN_ENABLED", "false")
    assert asn.enrich_ip("8.8.8.8") == (None, None, None, None)


def test_enrich_ip_returns_asn_prefix_and_source(tmp_path: Path) -> None:
    from decnet.asn import enrich_ip

    _seed_fixture(tmp_path)
    asn, name, prefix, src = enrich_ip("8.8.8.8")
    assert asn == 15169
    assert name == "GOOGLE"
    assert prefix == "8.8.8.0/24"
    assert src == "iptoasn"


def test_enrich_ip_private_returns_none(tmp_path: Path) -> None:
    from decnet.asn import enrich_ip

    _seed_fixture(tmp_path)
    assert enrich_ip("192.168.1.1") == (None, None, None, None)


def test_enrich_ip_unannounced_returns_none(tmp_path: Path) -> None:
    from decnet.asn import enrich_ip

    _seed_fixture(tmp_path)
    # 9.0.0.0 isn't in our fixture range — no BGP announcement we know of.
    assert enrich_ip("9.0.0.0") == (None, None, None, None)
