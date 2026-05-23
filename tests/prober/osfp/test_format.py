# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the p0f v2 .fp parser (decnet/prober/osfp/p0f/format.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

from decnet.prober.osfp.p0f.format import P0fParseError, _parse_line, parse_p0f_v2


# ─── Line-parser unit tests ──────────────────────────────────────────────────


def test_parse_line_minimal_literal() -> None:
    sig = _parse_line("5840:64:1:60:M1460,S,T,N,W7:.:Linux:2.6.x kernel")
    assert sig.os == "Linux"
    assert sig.flavor == "2.6.x kernel"
    assert sig.ttl == 64
    assert sig.df is True
    assert sig.wss.kind == "literal" and sig.wss.value == 5840
    assert sig.total_len.kind == "literal" and sig.total_len.value == 60
    assert len(sig.options) == 5
    # First option: MSS=1460
    mss_opt = sig.options[0]
    assert mss_opt.kind == "M"
    assert mss_opt.value is not None and mss_opt.value.value == 1460
    assert sig.quirks == frozenset()
    assert not sig.is_userland


def test_parse_line_wildcard_window() -> None:
    sig = _parse_line("*:128:1:*:M*,S,T,N,W*:.:Windows:XP SP1+")
    assert sig.wss.kind == "any"
    assert sig.total_len.kind == "any"
    assert sig.options[0].kind == "M"
    assert sig.options[0].value is not None and sig.options[0].value.kind == "any"


def test_parse_line_mss_multiple_window() -> None:
    sig = _parse_line("S4:64:1:60:M*,S,T,N,W*:.:Linux:generic")
    assert sig.wss.kind == "mss_mul" and sig.wss.value == 4


def test_parse_line_mtu_multiple_window() -> None:
    sig = _parse_line("T3:64:1:60:M*,S,T,N,W*:.:Solaris:10")
    assert sig.wss.kind == "mtu_mul" and sig.wss.value == 3


def test_parse_line_modulo_window() -> None:
    sig = _parse_line("%8192:64:1:60:M*,S,T,N,W*:.:Linux:probe")
    assert sig.wss.kind == "mod" and sig.wss.value == 8192


def test_parse_line_userland_prefix() -> None:
    sig = _parse_line("5840:64:1:60:M*,S,T,N,W*:.:-nmap:syn stealth")
    assert sig.is_userland is True
    assert sig.os == "nmap"


def test_parse_line_combined_prefixes() -> None:
    sig = _parse_line("5840:64:1:60:M*:.:-@Windows:fuzzy match")
    assert sig.is_userland is True
    assert sig.is_approximate is True
    assert sig.os == "Windows"


def test_parse_line_quirks_non_empty() -> None:
    sig = _parse_line("5840:64:1:60:M*,S,T,N,W*:PZ:Linux:with quirks")
    assert sig.quirks == frozenset({"P", "Z"})


def test_parse_line_no_options_sentinel() -> None:
    sig = _parse_line("5840:64:1:60:.:.:Linux:barebones")
    assert len(sig.options) == 1
    assert sig.options[0].kind == "."


def test_parse_line_t0_timestamp_distinct_from_t() -> None:
    sig = _parse_line("5840:64:1:60:M*,T0:.:Linux:broken timestamps")
    assert sig.options[1].kind == "T0"


def test_parse_line_unknown_option_number() -> None:
    sig = _parse_line("5840:64:1:60:M*,?47:.:Weird:stack")
    unknown = sig.options[1]
    assert unknown.kind == "?"
    assert unknown.value is not None and unknown.value.value == 47


def test_parse_line_rejects_too_few_fields() -> None:
    with pytest.raises(P0fParseError):
        _parse_line("5840:64:1:60")


def test_parse_line_rejects_bad_df() -> None:
    with pytest.raises(P0fParseError):
        _parse_line("5840:64:X:60:M*:.:Linux:bad")


def test_parse_line_rejects_bad_window_token() -> None:
    with pytest.raises(P0fParseError):
        _parse_line("Kfoo:64:1:60:M*:.:Linux:bad")


def test_parse_line_rejects_malformed_option() -> None:
    with pytest.raises(P0fParseError):
        _parse_line("5840:64:1:60:!!!wat:.:Linux:bad")


# ─── File-level tests ────────────────────────────────────────────────────────


def test_parse_file_skips_comments_blanks_bad_lines(tmp_path: Path) -> None:
    fp = tmp_path / "test.fp"
    fp.write_text(
        "# comment\n"
        "\n"
        "5840:64:1:60:M1460,S,T,N,W7:.:Linux:2.6.x\n"
        "# another comment\n"
        "garbage line that should skip\n"
        "8192:128:1:48:M1460,N,W0,N,N,S:.:Windows:XP\n"
    )
    sigs = parse_p0f_v2(fp)
    assert len(sigs) == 2
    assert {s.os for s in sigs} == {"Linux", "Windows"}


def test_parse_vendored_syn_db_fully_loads() -> None:
    """The full vendored p0f.fp MUST parse without losing signatures.
    Upstream inventory: 262 SYN signatures. A regression that drops rows
    would silently degrade OS-fingerprint coverage."""
    data = Path(__file__).resolve().parents[3] / "decnet/prober/osfp/p0f/data/p0f.fp"
    sigs = parse_p0f_v2(data)
    assert len(sigs) == 262, f"expected 262 SYN sigs, parser returned {len(sigs)}"


def test_parse_vendored_all_four_dbs_fully_load() -> None:
    """Same invariant across all four vendored databases."""
    base = Path(__file__).resolve().parents[3] / "decnet/prober/osfp/p0f/data"
    expected = {"p0f.fp": 262, "p0fa.fp": 61, "p0fr.fp": 46, "p0fo.fp": 6}
    for name, want in expected.items():
        sigs = parse_p0f_v2(base / name)
        assert len(sigs) == want, f"{name}: expected {want}, got {len(sigs)}"


def test_parse_vendored_specificity_in_range() -> None:
    """Every signature's computed specificity must land in [0, 1]."""
    data = Path(__file__).resolve().parents[3] / "decnet/prober/osfp/p0f/data/p0f.fp"
    for sig in parse_p0f_v2(data):
        assert 0.0 <= sig.specificity <= 1.0, (
            f"{sig.os}/{sig.flavor}: specificity out of range ({sig.specificity})"
        )
