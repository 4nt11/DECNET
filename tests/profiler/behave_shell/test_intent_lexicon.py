# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.0: command-intent lexicon + lexical counter pass.

No primitive emitted by this commit — it's the shared infrastructure
G.1-G.8 read from. Tests cover:

* hash-set sanity (no precedence-corrupting overlaps)
* :func:`classify_intent` returns the correct registry label
* the typed-text counter pass increments lexical counters and tracks
  caps / bang runs
* paste-class events do NOT contribute to the typed counters
* PII regression: counters land on ctx, no raw text on observations
"""
from __future__ import annotations

import json

from decnet.profiler.behave_shell import build_context, extract_session
from decnet.profiler.behave_shell._intent import (
    DESTRUCTIVE_TOKENS,
    EXFIL_TOKENS,
    INTENT_PRECEDENCE,
    LATERAL_TOKENS,
    LEXEME_MAX_LEN,
    NEGATIVE_LEXEMES,
    OBSCENITY_LEXEMES,
    OPSEC_HISTORY_TOKENS,
    PERSISTENCE_TOKENS,
    POSITIVE_LEXEMES,
    RECON_TOKENS,
    classify_intent,
)
from decnet.profiler.behave_shell._parse import AsciinemaEvent, hash_token


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def test_intent_sets_disjoint_where_precedence_matters() -> None:
    """``destructive`` and ``recon`` must not overlap — recon-only tokens
    should never accidentally classify as destructive (the high-precedence
    label). Cross-set overlap is *allowed*; precedence corruption is not.
    """
    # rm appears in destructive AND in some cleanup contexts elsewhere;
    # but recon must not accidentally pull a destructive token.
    assert not (RECON_TOKENS & DESTRUCTIVE_TOKENS)
    assert not (RECON_TOKENS & PERSISTENCE_TOKENS)
    assert not (LATERAL_TOKENS & EXFIL_TOKENS)


def test_classify_intent_returns_registry_labels() -> None:
    assert classify_intent(hash_token("rm")) == "destructive"
    assert classify_intent(hash_token("crontab")) == "persistence"
    assert classify_intent(hash_token("curl")) == "exfil"
    assert classify_intent(hash_token("ssh")) == "lateral"
    assert classify_intent(hash_token("ls")) == "recon"


def test_classify_intent_unknown_returns_none() -> None:
    assert classify_intent(hash_token("vim")) is None
    assert classify_intent(hash_token("nonsense_xyz")) is None


def test_lexicon_max_len_bounded() -> None:
    """Lexeme buffer can't grow without bound."""
    assert LEXEME_MAX_LEN >= max(len(x) for x in OBSCENITY_LEXEMES)
    assert LEXEME_MAX_LEN < 32  # sanity — single short word forms only


def test_obscenity_counter_fires_on_typed_token() -> None:
    """Typed ``fuck `` (with trailing boundary) increments
    ``obscenity_hits``; the lexeme is not retained as text."""
    events = _typed("fuck ")
    ctx = build_context(events, sid="g0-obs")
    assert ctx.obscenity_hits == 1
    assert ctx.positive_lex_hits == 0
    assert ctx.negative_lex_hits == 0


def test_lexeme_longest_match_fucking_counts_once() -> None:
    """``fucking`` is in the obscenity set; it should match once — not
    twice (``fuck`` + ``fucking``)."""
    events = _typed("fucking ")
    ctx = build_context(events, sid="g0-long")
    assert ctx.obscenity_hits == 1


def test_positive_and_negative_counters() -> None:
    events = _typed("nice work damn it ")
    ctx = build_context(events, sid="g0-mix")
    assert ctx.positive_lex_hits == 1   # nice
    assert ctx.negative_lex_hits == 1   # damn


def test_caps_run_max_tracks_longest_uppercase_streak() -> None:
    events = _typed("ok FUCK and OK ")
    ctx = build_context(events, sid="g0-caps")
    assert ctx.caps_run_max >= 4   # FUCK
    # obscenity is case-folded → still counts
    assert ctx.obscenity_hits >= 1


def test_bang_run_max_tracks_longest_bang_streak() -> None:
    events = _typed("wait!!! no!!\n")
    ctx = build_context(events, sid="g0-bang")
    assert ctx.bang_run_max == 3


def test_paste_class_events_excluded_from_lex_counters() -> None:
    """A pasted obscenity must NOT increment counters — paste-class
    events are the F.4 / G.0 boundary the operator's own typing is on
    one side of, pasted text on the other."""
    events: list[AsciinemaEvent] = [(0.0, "i", "fuck and shit pasted in")]
    ctx = build_context(events, sid="g0-paste")
    assert ctx.obscenity_hits == 0
    assert ctx.negative_lex_hits == 0


def test_no_lex_text_in_observation_values() -> None:
    """PII regression: lexeme word forms must not appear in any emitted
    observation's ``value`` field. (Primitive names like ``shell_type``
    legitimately contain ``hell`` — this test guards the data, not the
    schema.)"""
    events = _typed("oh fuck this is broken damn ")
    obs = list(extract_session(events, sid="g0-pii"))
    for o in obs:
        v_str = json.dumps(o.value)
        for lex in (OBSCENITY_LEXEMES | NEGATIVE_LEXEMES | POSITIVE_LEXEMES):
            assert lex not in v_str, (
                f"raw lexeme {lex!r} leaked into observation value "
                f"for primitive {o.primitive!r}: {o.value!r}"
            )


def test_intent_precedence_destructive_outranks_recon() -> None:
    """``rm`` must classify as destructive even though recon includes
    file-system tools."""
    h = hash_token("rm")
    assert h in DESTRUCTIVE_TOKENS
    assert classify_intent(h) == "destructive"
    # Sanity: the precedence tuple's first entry is destructive.
    assert INTENT_PRECEDENCE[0][0] == "destructive"


def test_opsec_history_tokens_populated() -> None:
    assert hash_token("history") in OPSEC_HISTORY_TOKENS
    assert hash_token("unset") in OPSEC_HISTORY_TOKENS
