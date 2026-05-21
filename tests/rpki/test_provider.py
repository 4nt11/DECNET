"""RipeStatValidator + factory + public API tests."""
from __future__ import annotations

import pytest


def test_factory_returns_ripestat_by_default() -> None:
    from decnet.rpki.factory import get_validator

    v = get_validator()
    assert v.name == "ripestat"


def test_factory_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from decnet.rpki import factory

    monkeypatch.setenv("DECNET_RPKI_PROVIDER", "nope")
    factory.reset_cache()
    with pytest.raises(ValueError):
        factory.get_validator()
    factory.reset_cache()


def test_enrich_rpki_short_circuits_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_RPKI_ENABLED", "false")
    from decnet.rpki import enrich_rpki

    assert enrich_rpki("8.8.8.8", 15169) == (None, None)


def test_enrich_rpki_short_circuits_when_asn_none() -> None:
    from decnet.rpki import enrich_rpki

    assert enrich_rpki("8.8.8.8", None) == (None, None)


def test_enrich_rpki_returns_status_and_source() -> None:
    from decnet.rpki import enrich_rpki

    status, source = enrich_rpki("8.8.8.8", 15169)
    assert status in {"valid", "invalid", "not-found", "unknown"}
    assert source == "ripestat"


def test_enrich_rpki_survives_validator_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    from decnet.rpki import factory as rpki_factory
    from decnet.rpki.base import Validator, RpkiResult

    class BrokenValidator(Validator):
        name = "broken"

        def validate(self, ip: str, asn: int) -> RpkiResult:
            raise RuntimeError("boom")

    monkeypatch.setattr(rpki_factory, "_cached", BrokenValidator())
    monkeypatch.setattr(rpki_factory, "_cached_key", "ripestat")

    from decnet.rpki import enrich_rpki

    assert enrich_rpki("8.8.8.8", 15169) == (None, None)
