"""``temporal.*`` feature functions — per-session subset.

Phase E ships the four ``temporal.*`` primitives that don't need
observation history. The other three (``session_timing``,
``persistence``, ``lifecycle_markers.idle_periodicity``) are Tier B
and computed by the attribution engine, not the extractor.

Step E.1: ``temporal.session_duration``.
Step E.2: ``temporal.escalation_pattern``.
"""
from __future__ import annotations

import math
import statistics
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    ESCALATION_BURSTY_CV,
    ESCALATION_BURSTY_ZERO_FRAC,
    ESCALATION_MIN_COMMANDS,
    ESCALATION_MIN_WINDOWS,
    ESCALATION_SUSTAINED_CV,
    ESCALATION_WINDOW_MIN_S,
    ESCALATION_WINDOW_TARGET,
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


def escalation_pattern(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``temporal.escalation_pattern`` ∈ {sustained, erratic, bursty}.

    Bin commands into non-overlapping windows of width
    ``max(ESCALATION_WINDOW_MIN_S, duration_s / ESCALATION_WINDOW_TARGET)``.
    Compute the CV of per-window command counts and the fraction of
    zero-count windows.

    * **bursty** — significant silence (zero_frac ≥ threshold) AND
      high dispersion (CV ≥ threshold). Real spikes against a quiet
      background.
    * **sustained** — low dispersion (CV < threshold). Steady cadence.
    * **erratic** — fall-through. Variable but no clear silence
      pattern.

    Skip emission when the session is too short to bin meaningfully
    (no commands, or duration too small to produce any window).
    """
    n_cmds = len(ctx.commands)
    if n_cmds == 0 or ctx.duration_s <= 0.0:
        return
    width = max(ESCALATION_WINDOW_MIN_S, ctx.duration_s / ESCALATION_WINDOW_TARGET)
    n_windows = max(1, math.ceil(ctx.duration_s / width))
    counts = [0] * n_windows
    for cmd in ctx.commands:
        offset = cmd.start_ts - ctx.t_start
        idx = min(n_windows - 1, max(0, int(offset / width)))
        counts[idx] += 1

    mean = statistics.fmean(counts)
    if mean <= 0.0 or len(counts) < 2:
        cv = 0.0
    else:
        cv = statistics.stdev(counts) / mean
    zero_frac = sum(1 for c in counts if c == 0) / len(counts)

    if zero_frac >= ESCALATION_BURSTY_ZERO_FRAC and cv >= ESCALATION_BURSTY_CV:
        value = "bursty"
    elif cv < ESCALATION_SUSTAINED_CV:
        value = "sustained"
    else:
        value = "erratic"

    if n_windows < ESCALATION_MIN_WINDOWS or n_cmds < ESCALATION_MIN_COMMANDS:
        confidence = 0.40
    else:
        confidence = 0.60
    yield make_observation(
        ctx,
        primitive="temporal.escalation_pattern",
        value=value,
        confidence=confidence,
    )
