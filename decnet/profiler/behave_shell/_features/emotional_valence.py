"""``emotional_valence.*`` feature functions (Phase G, soft block).

All four primitives in this module ride a hard 0.5 confidence cap
(:data:`EMOTIONAL_VALENCE_CONFIDENCE_CAP`). Cap is enforced inside
the feature functions, *not* via :func:`make_observation` — sample-size
honesty may still pull confidence below 0.5.

Step G.5: ``emotional_valence.valence``.
Step G.6: ``emotional_valence.arousal`` (lands later).
Step G.7: ``emotional_valence.stress_response`` (lands later).
Step G.8: ``emotional_valence.frustration_venting`` (lands later).
"""
from __future__ import annotations

from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    EMOTIONAL_VALENCE_CONFIDENCE_CAP,
    VALENCE_FULL_CONFIDENCE_MIN,
    VALENCE_MIN_HITS,
    VALENCE_MIN_TYPED_CHARS,
)


def _cap_soft(c: float) -> float:
    """Clamp confidence to the soft-primitive ceiling."""
    return min(c, EMOTIONAL_VALENCE_CONFIDENCE_CAP)


def valence(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``emotional_valence.valence`` ∈ {positive, neutral, negative}.

    Pure ratio over the lexical counters built in G.0:

    * ``positive`` — ``positive_lex_hits > negative_lex_hits +
      obscenity_hits`` AND ``positive_lex_hits ≥ VALENCE_MIN_HITS`` (2).
    * ``negative`` — ``negative_lex_hits + obscenity_hits >
      positive_lex_hits`` AND that sum ≥ ``VALENCE_MIN_HITS``.
    * ``neutral`` — fall-through.

    Skip emission below ``VALENCE_MIN_TYPED_CHARS`` (80) typed letters.
    Confidence hard-capped at 0.50 (registry convention); 0.30 below
    ``VALENCE_FULL_CONFIDENCE_MIN`` (200).
    """
    if ctx.typed_letter_count < VALENCE_MIN_TYPED_CHARS:
        return
    pos = ctx.positive_lex_hits
    neg_total = ctx.negative_lex_hits + ctx.obscenity_hits
    if pos > neg_total and pos >= VALENCE_MIN_HITS:
        value = "positive"
    elif neg_total > pos and neg_total >= VALENCE_MIN_HITS:
        value = "negative"
    else:
        value = "neutral"
    raw = 0.50 if ctx.typed_letter_count >= VALENCE_FULL_CONFIDENCE_MIN else 0.30
    yield make_observation(
        ctx,
        primitive="emotional_valence.valence",
        value=value,
        confidence=_cap_soft(raw),
    )
