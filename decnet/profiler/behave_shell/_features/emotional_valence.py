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

import statistics
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    AROUSAL_BANG_RUN_MIN,
    AROUSAL_CALM_IAT_S,
    AROUSAL_CAPS_RUN_MIN,
    AROUSAL_FAST_IAT_S,
    AROUSAL_MIN_IATS,
    EMOTIONAL_VALENCE_CONFIDENCE_CAP,
    STRESS_DISTRESS_RATIO_MIN,
    STRESS_EUSTRESS_RATIO_MIN,
    STRESS_MIN_ERRORED_WITH_IATS,
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


def arousal(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``emotional_valence.arousal`` ∈ {low_calm, medium_engaged,
    high_agitated}.

    Three signals (any of which fires ``high_agitated``):

    * ``ctx.caps_run_max ≥ AROUSAL_CAPS_RUN_MIN`` (5) — capslock rant.
    * ``ctx.bang_run_max ≥ AROUSAL_BANG_RUN_MIN`` (3) — repeated bangs.
    * The fastest typing burst's median IAT < ``AROUSAL_FAST_IAT_S``
      (0.06) over a burst of ≥ ``AROUSAL_MIN_IATS`` (30) IATs.

    ``low_calm`` — slowest qualifying burst's median IAT >
    ``AROUSAL_CALM_IAT_S`` (0.30).

    ``medium_engaged`` — fall-through.

    Skip emission when no qualifying typing bursts. Confidence hard-
    capped at 0.50; 0.30 below ``AROUSAL_MIN_IATS`` total typed IATs.
    """
    qualifying = [b for b in ctx.typing_bursts if len(b) >= 3]
    if not qualifying:
        return
    fastest_med = min(statistics.median(b) for b in qualifying)
    slowest_med = max(statistics.median(b) for b in qualifying)
    total_iats = sum(len(b) for b in qualifying)

    if (
        ctx.caps_run_max >= AROUSAL_CAPS_RUN_MIN
        or ctx.bang_run_max >= AROUSAL_BANG_RUN_MIN
        or (
            total_iats >= AROUSAL_MIN_IATS
            and fastest_med < AROUSAL_FAST_IAT_S
        )
    ):
        value = "high_agitated"
    elif total_iats >= AROUSAL_MIN_IATS and slowest_med > AROUSAL_CALM_IAT_S:
        value = "low_calm"
    else:
        value = "medium_engaged"
    raw = 0.50 if total_iats >= AROUSAL_MIN_IATS else 0.30
    yield make_observation(
        ctx,
        primitive="emotional_valence.arousal",
        value=value,
        confidence=_cap_soft(raw),
    )


def stress_response(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``emotional_valence.stress_response`` ∈ {none,
    eustress_positive, distress_negative}.

    Compare typing speed *after* an errored command vs the session
    baseline:

    * For each errored command at index ``i``, gather
      ``ctx.intra_command_iats[i+1]`` — the response command's intra-
      command IATs.
    * Baseline: median of all intra-command IATs from commands NOT
      immediately following an errored command.

    Verdict by ratio of post-error / baseline:

    * ratio ≥ ``STRESS_EUSTRESS_RATIO_MIN`` (1.20) → ``eustress_positive``
      (slowed down — recovered, deliberate).
    * ratio ≤ ``1 / STRESS_DISTRESS_RATIO_MIN`` → ``distress_negative``
      (sped up — anxious, mashing keys).
    * otherwise → ``none``.

    Skip emission when no commands. Confidence hard-capped at 0.50;
    0.30 below ``STRESS_MIN_ERRORED_WITH_IATS`` (2) errored commands
    with non-empty post-error IAT data.
    """
    if not ctx.commands:
        return
    post_error_iats: list[float] = []
    baseline_iats: list[float] = []
    n = len(ctx.commands)
    qualifying_errored = 0
    for i, cmd in enumerate(ctx.commands):
        is_post_error = i > 0 and ctx.commands[i - 1].errored
        iats = list(ctx.intra_command_iats[i]) if i < len(ctx.intra_command_iats) else []
        if is_post_error:
            if iats:
                qualifying_errored += 1
                post_error_iats.extend(iats)
        else:
            baseline_iats.extend(iats)
        # mypy: silence unused-var on n / cmd (kept for clarity)
        _ = (n, cmd)
    if not post_error_iats or not baseline_iats:
        value = "none"
    else:
        med_post = statistics.median(post_error_iats)
        med_base = statistics.median(baseline_iats)
        if med_base <= 0.0:
            value = "none"
        else:
            ratio = med_post / med_base
            if ratio >= STRESS_EUSTRESS_RATIO_MIN:
                value = "eustress_positive"
            elif ratio <= 1.0 / STRESS_DISTRESS_RATIO_MIN:
                value = "distress_negative"
            else:
                value = "none"
    raw = 0.50 if qualifying_errored >= STRESS_MIN_ERRORED_WITH_IATS else 0.30
    yield make_observation(
        ctx,
        primitive="emotional_valence.stress_response",
        value=value,
        confidence=_cap_soft(raw),
    )
