"""``motor.*`` feature functions.

Step 2: ``motor.input_modality`` — typed / pasted / mixed.
Step 3: ``motor.paste_burst_rate`` — none / occasional / habitual.
Step B.1: ``motor.keystroke_cadence`` — steady / bursty / hunt_and_peck / machine.
"""
from __future__ import annotations

import statistics
from itertools import chain
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    CV_BURSTY_MAX,
    CV_MACHINE_MAX,
    CV_STEADY_MAX,
    IKI_MACHINE_MAX_S,
    MIN_INPUTS_FOR_CADENCE,
    MODALITY_PASTED_MIN,
    MODALITY_TYPED_MAX,
    PASTE_RATE_HABITUAL_MIN,
    PASTE_RATE_OCCASIONAL_MIN,
)


def input_modality(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.input_modality`` ∈ {typed, pasted, mixed}.

    Ratio of paste-class events to total inputs. Empty input → skip
    emission entirely (the registry doesn't admit ``unknown`` here
    and fabricating ``typed`` for a zero-input session is dishonest).
    """
    n = len(ctx.input_events)
    if n == 0:
        return
    ratio = ctx.paste_event_count / n
    if ratio >= MODALITY_PASTED_MIN:
        modality = "pasted"
        confidence = 0.75
    elif ratio <= MODALITY_TYPED_MAX:
        modality = "typed"
        confidence = 0.75
    else:
        modality = "mixed"
        confidence = 0.70
    yield make_observation(
        ctx,
        primitive="motor.input_modality",
        value=modality,
        confidence=confidence,
    )


def paste_burst_rate(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.paste_burst_rate`` ∈ {none, occasional, habitual}.

    Same paste-event ratio as ``input_modality`` but coarser-bucketed:
    this primitive is the *habit* signal (does the operator reach for
    paste at all?), where input_modality is the dominant-channel
    signal (is the session paste-driven overall?). Splits YOU-sim from
    LW/CLAUDE-FF/CLAUDE-CL — LLM-driven sessions paste habitually,
    real humans don't.
    """
    n = len(ctx.input_events)
    if n == 0:
        return
    ratio = ctx.paste_event_count / n
    if ratio >= PASTE_RATE_HABITUAL_MIN:
        level = "habitual"
        confidence = 0.80
    elif ratio >= PASTE_RATE_OCCASIONAL_MIN:
        level = "occasional"
        confidence = 0.70
    else:
        level = "none"
        confidence = 0.70
    yield make_observation(
        ctx,
        primitive="motor.paste_burst_rate",
        value=level,
        confidence=confidence,
    )


def keystroke_cadence(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.keystroke_cadence`` ∈ {steady, bursty, hunt_and_peck, machine}.

    Median CV of within-typing-burst IATs (bursts split at gaps >
    ``IKI_THINK_MAX_S`` so think-pauses between commands don't
    inflate the variance). Pasted-only sessions and sessions below
    ``MIN_INPUTS_FOR_CADENCE`` skip emission — no honest cadence
    available.

    v0.1 emits only the burst-CV variant. The prototype's NAIVE
    session-CV variant (lower confidence, second emission per
    primitive) is parked for v0.2.
    """
    if len(ctx.input_events) < MIN_INPUTS_FOR_CADENCE:
        return
    if not ctx.typing_bursts:
        return
    burst_cvs: list[float] = []
    for b in ctx.typing_bursts:
        m = statistics.fmean(b)
        if m > 0:
            burst_cvs.append(statistics.pstdev(b) / m)
    if not burst_cvs:
        return
    cv = statistics.median(burst_cvs)
    mean_iki = statistics.fmean(chain.from_iterable(ctx.typing_bursts))
    if mean_iki < IKI_MACHINE_MAX_S and cv < CV_MACHINE_MAX:
        value, confidence = "machine", 0.85
    elif cv < CV_STEADY_MAX:
        value, confidence = "steady", 0.70
    elif cv < CV_BURSTY_MAX:
        value, confidence = "bursty", 0.65
    else:
        value, confidence = "hunt_and_peck", 0.60
    yield make_observation(
        ctx,
        primitive="motor.keystroke_cadence",
        value=value,
        confidence=confidence,
    )
