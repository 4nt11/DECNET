"""Tests for signature matching + scoring."""
from __future__ import annotations

import pytest

from decnet.prober.osfp.p0f.format import _parse_line


def _obs(**overrides):
    """Baseline observation (Linux 2.6 on Ethernet), overridable."""
    base = {
        "window": 5840,
        "ttl": 64,
        "df": True,
        "total_len": 60,
        "options_sig": "M1460,S,T,N,W7",
        "quirks": frozenset(),
        "mss": 1460,
        "wscale": 7,
    }
    base.update(overrides)
    return base


# ─── Match / no-match ────────────────────────────────────────────────────────


def test_score_exact_match_is_high() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:2.6.x literal")
    score = sig.score(_obs())
    assert score is not None
    assert score >= 0.9, f"literal-fields signature should score high, got {score}"


def test_score_wildcard_match_is_lower_than_literal() -> None:
    literal = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:literal")
    wildcard = _parse_line("*:64:1:*:M*,S,T,N,W*:.:Linux:wildcard")
    obs = _obs()
    ls = literal.score(obs)
    ws = wildcard.score(obs)
    assert ls is not None and ws is not None
    assert ls > ws, f"literal ({ls}) should outscore wildcard ({ws})"


def test_score_window_mismatch_returns_none() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:fixed")
    assert sig.score(_obs(window=64240)) is None


def test_score_ttl_mismatch_returns_none() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:ttl64")
    assert sig.score(_obs(ttl=128)) is None


def test_score_df_mismatch_returns_none() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:df-required")
    assert sig.score(_obs(df=False)) is None


def test_score_df_wildcard_on_signature_matches_either() -> None:
    sig = _parse_line("5840:64:*:60:M1460,S,T,N,W7:.:Linux:any-df")
    assert sig.score(_obs(df=True)) is not None
    assert sig.score(_obs(df=False)) is not None


def test_score_df_none_on_observation_is_soft_skip() -> None:
    """When the observation lacks df (sniffer doesn't emit it today),
    a signature with a specific df constraint must still match rather
    than hard-reject. Rationale in the score() docstring."""
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:df-required")
    assert sig.score(_obs(df=None)) is not None


def test_score_total_len_none_on_observation_is_soft_skip() -> None:
    """Same soft-field semantics for total_len — the profiler adapter
    passes None when the sniffer / prober didn't capture it."""
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:len-specific")
    assert sig.score(_obs(total_len=None)) is not None


def test_score_options_order_mismatch_returns_none() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:ordered")
    # Same tokens, different order — must NOT match.
    assert sig.score(_obs(options_sig="S,T,M1460,N,W7")) is None


def test_score_options_missing_token_returns_none() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:5opts")
    assert sig.score(_obs(options_sig="M1460,S,T,N")) is None


def test_score_quirks_must_match_as_set() -> None:
    sig = _parse_line("5840:64:1:60:M*,S,T,N,W*:PZ:Linux:with PZ")
    assert sig.score(_obs(quirks=frozenset({"P", "Z"}))) is not None
    assert sig.score(_obs(quirks=frozenset({"P"}))) is None  # missing Z
    assert sig.score(_obs(quirks=frozenset({"P", "Z", "I"}))) is None  # extra I


def test_score_mss_multiple_window() -> None:
    # S4 = 4 * MSS. With MSS=1460 → window=5840.
    sig = _parse_line("S4:64:1:60:M1460,S,T,N,W7:.:Linux:S4")
    assert sig.score(_obs(window=5840, mss=1460)) is not None
    # With MSS=536 → S4 expects window=2144
    assert sig.score(_obs(window=2144, mss=536)) is not None
    assert sig.score(_obs(window=5840, mss=536)) is None


def test_score_modulo_window() -> None:
    sig = _parse_line("%8192:64:1:60:M1460,S,T,N,W7:.:Linux:mod8192")
    assert sig.score(_obs(window=32768)) is not None
    assert sig.score(_obs(window=40960)) is not None
    assert sig.score(_obs(window=32769)) is None


def test_score_no_options_sentinel() -> None:
    sig = _parse_line("5840:64:1:60:.:.:Linux:no-opts")
    assert sig.score(_obs(options_sig="")) is not None
    assert sig.score(_obs(options_sig=None)) is not None
    assert sig.score(_obs(options_sig="M1460")) is None


def test_score_missing_observation_fields_returns_none() -> None:
    """A signature that requires a specific window can't match when the
    observation has no window. This is the safety invariant —
    sniffer_rollup may call score() with partial data."""
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:strict")
    assert sig.score(_obs(window=None)) is None
    assert sig.score(_obs(ttl=None)) is None


def test_score_option_value_wildcard_matches_any_literal() -> None:
    sig = _parse_line("5840:64:1:60:M*,S,T,N,W*:.:Linux:wild-mss-wscale")
    assert sig.score(_obs(options_sig="M1460,S,T,N,W7")) is not None
    assert sig.score(_obs(options_sig="M536,S,T,N,W2")) is not None


def test_score_option_value_modulo() -> None:
    sig = _parse_line("5840:64:1:60:M%4,S,T,N,W7:.:Linux:mss-mod-4")
    assert sig.score(_obs(options_sig="M1460,S,T,N,W7")) is not None  # 1460 % 4 == 0
    assert sig.score(_obs(options_sig="M1461,S,T,N,W7")) is None
