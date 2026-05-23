# SPDX-License-Identifier: AGPL-3.0-or-later
"""Integration tests for P0fV2Provider against the vendored .fp data."""
from __future__ import annotations

from pathlib import Path

import pytest

from decnet.prober.osfp import factory, get_all_providers, get_provider
from decnet.prober.osfp.base import OsMatch
from decnet.prober.osfp.p0f.provider import P0fV2Provider


@pytest.fixture(autouse=True)
def _reset_factory_cache():
    """Clean singleton between tests so env overrides take effect."""
    factory.reset_cache()
    yield
    factory.reset_cache()


# ─── Provider-level end-to-end ───────────────────────────────────────────────


def test_provider_loads_all_four_contexts() -> None:
    p = P0fV2Provider()
    counts = p.signature_counts()
    assert counts["syn"] == 262, counts
    assert counts["synack"] == 61, counts
    assert counts["rst"] == 46, counts
    assert counts["stray"] == 6, counts


def test_match_known_linux_26_signature() -> None:
    """Linux 2.6 with window=5840, MSS=1460, wscale=7 is in the
    vendored p0f.fp — must resolve to a Linux match."""
    p = P0fV2Provider()
    obs = {
        "window": 5840, "ttl": 64, "df": True, "total_len": 60,
        "options_sig": "M1460,S,T,N,W7", "quirks": frozenset(),
        "mss": 1460, "wscale": 7, "context": "syn",
    }
    match = p.match(obs)
    assert match is not None
    assert match.os == "Linux"
    assert match.provider == "p0f-v2"
    assert match.confidence > 0.5


def test_match_returns_none_for_unmatchable_observation() -> None:
    p = P0fV2Provider()
    # Ridiculous values with no corresponding signature.
    obs = {
        "window": 999999, "ttl": 64, "df": True, "total_len": 9999,
        "options_sig": "?255,?254", "quirks": frozenset(),
        "mss": 9999, "wscale": 99, "context": "syn",
    }
    assert p.match(obs) is None


def test_match_unknown_context_returns_none() -> None:
    p = P0fV2Provider()
    obs = {"window": 5840, "ttl": 64, "df": True, "total_len": 60,
           "options_sig": "M1460", "quirks": frozenset(),
           "mss": 1460, "context": "impossible"}
    assert p.match(obs) is None


def test_match_missing_context_defaults_to_syn() -> None:
    p = P0fV2Provider()
    obs = {
        "window": 5840, "ttl": 64, "df": True, "total_len": 60,
        "options_sig": "M1460,S,T,N,W7", "quirks": frozenset(),
        "mss": 1460, "wscale": 7,
        # no 'context' key
    }
    match = p.match(obs)
    assert match is not None
    assert match.os == "Linux"


def test_match_synack_context_uses_p0fa() -> None:
    """Sanity: active-probe SYN-ACK observations resolve against the
    61-sig p0fa.fp list, not the 262-sig p0f.fp list.

    Targeting "S22:64:1:60:M*,S,T,N,W0:AT:Linux:2.2" from p0fa.fp
    (ACK quirk + second-timestamp quirk are characteristic of SYN-ACK
    responses, distinguishing these sigs from the plain-SYN DB)."""
    p = P0fV2Provider()
    obs = {
        "window": 22 * 1460, "ttl": 64, "df": True, "total_len": 60,
        "options_sig": "M1460,S,T,N,W0",
        "quirks": frozenset({"A", "T"}),   # ACK-nonzero + T2-nonzero
        "mss": 1460, "wscale": 0, "context": "synack",
    }
    match = p.match(obs)
    assert match is not None
    assert match.os == "Linux"


def test_match_returns_highest_specificity_not_first() -> None:
    """When multiple signatures can fire, the provider must pick the
    most-specific one. Proxy for this: a Linux-style observation that
    could be caught by an @generic fallback AND a literal-Linux sig must
    resolve to the literal one (higher confidence)."""
    p = P0fV2Provider()
    obs = {
        "window": 5840, "ttl": 64, "df": True, "total_len": 60,
        "options_sig": "M1460,S,T,N,W7", "quirks": frozenset(),
        "mss": 1460, "wscale": 7, "context": "syn",
    }
    match = p.match(obs)
    # An @generic match would carry is_approximate=True on the underlying
    # signature — we can't check that through OsMatch directly, but we can
    # check confidence: literal-heavy sigs score notably higher than the
    # wildcard-heavy @-fallbacks, so a healthy match is ≥ 0.6.
    assert match is not None
    assert match.confidence >= 0.6


# ─── Factory dispatch ───────────────────────────────────────────────────────


def test_factory_default_is_p0f_v2() -> None:
    p = get_provider()
    assert p.name == "p0f-v2"
    assert isinstance(p, P0fV2Provider)


def test_factory_is_memoised() -> None:
    assert get_provider() is get_provider()


def test_factory_get_all_providers_returns_list() -> None:
    providers = get_all_providers()
    assert len(providers) >= 1
    assert providers[0].name == "p0f-v2"


def test_factory_env_override_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """Multi-provider chain must preserve declared order."""
    monkeypatch.setenv("DECNET_OSFP_PROVIDERS", "p0f-v2")
    factory.reset_cache()
    providers = get_all_providers()
    assert [p.name for p in providers] == ["p0f-v2"]


def test_factory_unsupported_name_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_OSFP_PROVIDERS", "nonexistent-source")
    factory.reset_cache()
    with pytest.raises(ValueError):
        get_provider()


def test_factory_reserved_names_raise_not_implemented(monkeypatch: pytest.MonkeyPatch) -> None:
    """nmap-osdb and decnet-observed are reserved for future work; the
    factory must fail loud rather than silently."""
    for reserved in ("nmap-osdb", "decnet-observed"):
        monkeypatch.setenv("DECNET_OSFP_PROVIDERS", reserved)
        factory.reset_cache()
        with pytest.raises(NotImplementedError):
            get_provider()


# ─── OsMatch surface ────────────────────────────────────────────────────────


def test_osmatch_str_shows_provider() -> None:
    match = OsMatch(os="Linux", flavor="2.6", confidence=0.8, provider="p0f-v2")
    s = str(match)
    assert "Linux" in s and "2.6" in s and "p0f-v2" in s


def test_osmatch_userland_flag_marks_scanner() -> None:
    match = OsMatch(os="nmap", flavor="syn-stealth", confidence=0.9,
                    provider="p0f-v2", is_userland=True)
    assert match.is_userland
    assert "userland" in str(match).lower()
