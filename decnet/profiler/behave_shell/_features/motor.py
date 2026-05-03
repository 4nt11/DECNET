"""``motor.*`` feature functions.

Step 2: ``motor.input_modality`` — typed / pasted / mixed.
Step 3: ``motor.paste_burst_rate`` — none / occasional / habitual.
"""
from __future__ import annotations

from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
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
