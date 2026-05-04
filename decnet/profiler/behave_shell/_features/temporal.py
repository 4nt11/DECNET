"""``temporal.*`` feature functions — per-session subset.

Phase E ships the four ``temporal.*`` primitives that don't need
observation history. The other three (``session_timing``,
``persistence``, ``lifecycle_markers.idle_periodicity``) are Tier B
and computed by the attribution engine, not the extractor.

Step E.1: ``temporal.session_duration``.
"""
from __future__ import annotations

from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    SESSION_DURATION_LONG_MAX,
    SESSION_DURATION_MEDIUM_MAX,
    SESSION_DURATION_SHORT_MAX,
)


def session_duration(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``temporal.session_duration`` ∈ {short, medium, long, marathon}.

    Direct measurement off ``ctx.duration_s``. Skip emission only when
    the session has neither commands nor any duration to speak of —
    a one-event session with ``duration_s == 0`` and no commands has
    nothing honest to bucket. Confidence is high — duration is a fact,
    not an inference.
    """
    if ctx.duration_s <= 0.0 and not ctx.commands:
        return
    d = ctx.duration_s
    if d < SESSION_DURATION_SHORT_MAX:
        value = "short"
    elif d < SESSION_DURATION_MEDIUM_MAX:
        value = "medium"
    elif d < SESSION_DURATION_LONG_MAX:
        value = "long"
    else:
        value = "marathon"
    yield make_observation(
        ctx,
        primitive="temporal.session_duration",
        value=value,
        confidence=0.85,
    )
