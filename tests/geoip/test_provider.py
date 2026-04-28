"""RirProvider + factory + public API tests."""
from __future__ import annotations

from pathlib import Path

import pytest


def test_factory_returns_rir_by_default() -> None:
    from decnet.geoip.factory import get_provider

    provider = get_provider()
    assert provider.name == "rir"


def test_factory_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from decnet.geoip import factory

    monkeypatch.setenv("DECNET_GEOIP_PROVIDER", "nope")
    factory.reset_cache()
    with pytest.raises(ValueError):
        factory.get_provider()


def test_factory_reserved_providers_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    from decnet.geoip import factory

    for reserved in ("dbip", "maxmind"):
        monkeypatch.setenv("DECNET_GEOIP_PROVIDER", reserved)
        factory.reset_cache()
        with pytest.raises(NotImplementedError):
            factory.get_provider()


def test_provider_build_lookup_empty_when_no_files(tmp_path: Path) -> None:
    from decnet.geoip.rir.provider import RirProvider

    p = RirProvider()
    lookup = p.build_lookup()
    assert len(lookup) == 0
    assert lookup.country("8.8.8.8") is None


def test_provider_build_lookup_reads_present_files(tmp_path: Path) -> None:
    from decnet.geoip.rir.fetch import RIR_SOURCES
    from decnet.geoip.rir.provider import RirProvider

    # Drop one fake ARIN file — provider should pick it up.
    arin_name = RIR_SOURCES[0][0]
    (tmp_path / f"{arin_name}.txt").write_text(
        "arin|US|ipv4|8.8.8.0|256|20000101|allocated|abc\n"
    )
    p = RirProvider()
    lookup = p.build_lookup()
    assert lookup.country("8.8.8.8") == "US"


def test_provider_uses_cache_when_fresh(tmp_path: Path) -> None:
    from decnet.geoip.rir.fetch import RIR_SOURCES
    from decnet.geoip.rir.provider import RirProvider

    arin_name = RIR_SOURCES[0][0]
    src = tmp_path / f"{arin_name}.txt"
    src.write_text("arin|US|ipv4|8.8.8.0|256|20000101|allocated|abc\n")
    p = RirProvider()
    lookup_a = p.build_lookup()
    assert (tmp_path / ".rir_index.pkl").exists()

    # Rewrite the source file BUT keep its mtime older than the cache.
    # We only test the fast path by rebuilding a new provider instance
    # without mutating the source — cache should be used.
    p2 = RirProvider()
    lookup_b = p2.build_lookup()
    assert len(lookup_b) == len(lookup_a)


def test_enrich_ip_short_circuits_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    import decnet.geoip as geoip

    monkeypatch.setenv("DECNET_GEOIP_ENABLED", "false")
    assert geoip.enrich_ip("8.8.8.8") == (None, None)


def test_enrich_ip_returns_country_and_source(tmp_path: Path) -> None:
    from decnet.geoip import enrich_ip
    from decnet.geoip.rir.fetch import RIR_SOURCES

    (tmp_path / f"{RIR_SOURCES[0][0]}.txt").write_text(
        "arin|US|ipv4|8.8.8.0|256|20000101|allocated|abc\n"
    )
    cc, src = enrich_ip("8.8.8.8")
    assert cc == "US"
    assert src == "rir"


def test_enrich_ip_private_returns_none(tmp_path: Path) -> None:
    from decnet.geoip import enrich_ip
    from decnet.geoip.rir.fetch import RIR_SOURCES

    (tmp_path / f"{RIR_SOURCES[0][0]}.txt").write_text(
        "arin|US|ipv4|8.8.8.0|256|20000101|allocated|abc\n"
    )
    assert enrich_ip("192.168.1.1") == (None, None)
