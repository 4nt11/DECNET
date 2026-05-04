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
    BACKSPACE_IMMEDIATE_MAX_S,
    CMD_CHUNKING_FLUENT_CV_MAX,
    CV_BURSTY_MAX,
    CV_MACHINE_MAX,
    CV_STEADY_MAX,
    IKI_MACHINE_MAX_S,
    MIN_INPUTS_FOR_CADENCE,
    MODALITY_PASTED_MIN,
    MODALITY_TYPED_MAX,
    PASTE_RATE_HABITUAL_MIN,
    PASTE_RATE_OCCASIONAL_MIN,
    SHELL_MASTERY_BOUNDARY_BAND,
    SHELL_MASTERY_MIN_COMMANDS,
    PIPE_CHAINING_DEEP_MEDIAN,
    PIPE_CHAINING_MODERATE_MEDIAN,
    SHORTCUT_USAGE_HEAVY_MIN,
    SHORTCUT_USAGE_MODERATE_MIN,
    TAB_COMPLETION_HABITUAL_MIN,
    TAB_COMPLETION_OCCASIONAL_MAX,
    TREMOR_FAST_FLOOR_S,
    TREMOR_RATE_MIN,
)


def _near(value: float, boundary: float) -> bool:
    """True iff ``value`` is within ``SHELL_MASTERY_BOUNDARY_BAND`` of
    ``boundary`` (relative to the boundary). Phase C uses this to drop
    confidence when a measurement sits on a bucket fence.
    """
    if boundary == 0:
        return abs(value) <= SHELL_MASTERY_BOUNDARY_BAND
    return abs(value - boundary) / boundary <= SHELL_MASTERY_BOUNDARY_BAND


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


def motor_stability(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.motor_stability`` ∈ {steady, variable, tremor}.

    First-pass tremor signal: fraction of within-typing-burst IATs
    below ``TREMOR_FAST_FLOOR_S`` (30 ms — humans can't reliably
    produce sustained sub-50 ms IATs). High sub-floor rate flags
    double-press / motor twitch / stuck-key. Otherwise the same
    median burst-CV used by ``keystroke_cadence`` decides
    steady-vs-variable, with the cadence's CV_STEADY_MAX as the
    boundary.
    """
    if not ctx.typing_bursts:
        return
    flat = list(chain.from_iterable(ctx.typing_bursts))
    if len(flat) < 5:
        return
    fast_rate = sum(1 for x in flat if x < TREMOR_FAST_FLOOR_S) / len(flat)
    if fast_rate >= TREMOR_RATE_MIN:
        value, confidence = "tremor", 0.65
    else:
        burst_cvs: list[float] = []
        for b in ctx.typing_bursts:
            m = statistics.fmean(b)
            if m > 0:
                burst_cvs.append(statistics.pstdev(b) / m)
        cv = statistics.median(burst_cvs) if burst_cvs else 0.0
        if cv < CV_STEADY_MAX:
            value, confidence = "steady", 0.70
        else:
            value, confidence = "variable", 0.60
    yield make_observation(
        ctx,
        primitive="motor.motor_stability",
        value=value,
        confidence=confidence,
    )


def error_correction(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.error_correction`` ∈ {immediate, deferred, absent, route_around}.

    Backspace timing relative to the preceding non-backspace key:

    * 0 backspaces + ≥1 ^U/^W → ``route_around`` (operator killed
      the line and rewrote rather than correcting in place).
    * 0 backspaces + 0 ^U/^W → ``absent`` (no correction observed).
    * Backspaces with median IAT ≤ ``BACKSPACE_IMMEDIATE_MAX_S``
      (500 ms) → ``immediate`` (caught the typo mid-keystroke).
    * Slower → ``deferred`` (paused, noticed, then went back).

    < 3 input events → skip emission.
    """
    if len(ctx.input_events) < 3:
        return
    if ctx.backspace_count == 0:
        if ctx.kill_line_count > 0:
            value, confidence = "route_around", 0.55
        else:
            value, confidence = "absent", 0.65
    else:
        if ctx.backspace_iats:
            med = statistics.median(ctx.backspace_iats)
        else:
            med = float("inf")
        if med <= BACKSPACE_IMMEDIATE_MAX_S:
            value, confidence = "immediate", 0.65
        else:
            value, confidence = "deferred", 0.55
    yield make_observation(
        ctx,
        primitive="motor.error_correction",
        value=value,
        confidence=confidence,
    )


def command_chunking(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.command_chunking`` ∈ {fluent, fragmented, single_command}.

    * 0 commands → skip (no honest answer).
    * 1 command → ``single_command`` (registry-allowed, distinct from
      the fluent/fragmented continuum that needs multiple commands).
    * ≥2 commands → median CV across per-command intra-typing IATs;
      below ``CMD_CHUNKING_FLUENT_CV_MAX`` → fluent, else fragmented.

    Skips emission if no command has ≥3 typed IATs to compute a CV
    over (paste-driven sessions where every command arrived as one
    bulk write — no honest within-command rhythm to measure).
    """
    n = len(ctx.commands)
    if n == 0:
        return
    if n == 1:
        yield make_observation(
            ctx,
            primitive="motor.command_chunking",
            value="single_command",
            confidence=0.80,
        )
        return
    cvs: list[float] = []
    for iats in ctx.intra_command_iats:
        if len(iats) < 3:
            continue
        m = statistics.fmean(iats)
        if m > 0:
            cvs.append(statistics.pstdev(iats) / m)
    if not cvs:
        return
    cv = statistics.median(cvs)
    if cv < CMD_CHUNKING_FLUENT_CV_MAX:
        value, confidence = "fluent", 0.65
    else:
        value, confidence = "fragmented", 0.60
    yield make_observation(
        ctx,
        primitive="motor.command_chunking",
        value=value,
        confidence=confidence,
    )


def tab_completion(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.shell_mastery.tab_completion`` ∈ {none, occasional, habitual}.

    Metric: fraction of commands containing at least one ``\\t`` keystroke.
    A pasted full command line that happens to embed a tab still counts —
    the operator chose to send the bytes — but in practice tab keystrokes
    only arrive interactively, so this is dominated by typed sessions.

    Confidence:
    * < ``SHELL_MASTERY_MIN_COMMANDS`` → 0.40 (sample-size honesty).
    * Within ±10% of either bucket boundary → 0.55 (threshold proximity).
    * Otherwise → 0.75.

    Skips emission when the session has no commands at all (no honest
    ratio to report; the registry doesn't admit ``unknown`` here).
    """
    n = len(ctx.commands)
    if n == 0:
        return
    commands_with_tab = sum(1 for c in ctx.commands if c.tab_count > 0)
    ratio = commands_with_tab / n

    if ratio == 0.0:
        value = "none"
    elif ratio < TAB_COMPLETION_OCCASIONAL_MAX:
        value = "occasional"
    elif ratio < TAB_COMPLETION_HABITUAL_MIN:
        # Registry's own gap (30%-<50%) — round down rather than up.
        value = "occasional"
    else:
        value = "habitual"

    if n < SHELL_MASTERY_MIN_COMMANDS:
        confidence = 0.40
    elif (
        _near(ratio, TAB_COMPLETION_OCCASIONAL_MAX)
        or _near(ratio, TAB_COMPLETION_HABITUAL_MIN)
    ):
        confidence = 0.55
    else:
        confidence = 0.75

    yield make_observation(
        ctx,
        primitive="motor.shell_mastery.tab_completion",
        value=value,
        confidence=confidence,
    )


def shortcut_usage(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.shell_mastery.shortcut_usage`` ∈ {none, moderate, heavy}.

    Metric: total readline ctrl-byte keystrokes (the seven in
    :data:`SHORTCUT_CTRL_BYTES`) divided by command count. Registry
    buckets are qualitative; v0.1 thresholds are pinned for corpus
    calibration. Heavy users tend to be tmux/zsh/bash power operators
    who edit lines in place rather than retyping.

    Confidence:
    * < ``SHELL_MASTERY_MIN_COMMANDS`` → 0.40.
    * Within ±10% of either bucket boundary → 0.55.
    * Otherwise → 0.65 (lower than tab_completion: thresholds are
      not yet corpus-calibrated, mirrors ``motor_stability`` posture).

    Skips emission when the session has no commands at all.
    """
    n = len(ctx.commands)
    if n == 0:
        return
    total_shortcuts = sum(c.shortcut_count for c in ctx.commands)
    rate = total_shortcuts / n

    if total_shortcuts == 0 or rate < SHORTCUT_USAGE_MODERATE_MIN:
        value = "none"
    elif rate < SHORTCUT_USAGE_HEAVY_MIN:
        value = "moderate"
    else:
        value = "heavy"

    if n < SHELL_MASTERY_MIN_COMMANDS:
        confidence = 0.40
    elif (
        _near(rate, SHORTCUT_USAGE_MODERATE_MIN)
        or _near(rate, SHORTCUT_USAGE_HEAVY_MIN)
    ):
        confidence = 0.55
    else:
        confidence = 0.65

    yield make_observation(
        ctx,
        primitive="motor.shell_mastery.shortcut_usage",
        value=value,
        confidence=confidence,
    )


def pipe_chaining_depth(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``motor.shell_mastery.pipe_chaining_depth`` ∈ {shallow, moderate, deep}.

    Metric: median ``|`` count across commands. Pipes are counted on
    every byte regardless of whether they came from a paste-burst —
    a pasted pipeline is still a pipeline the operator chose to run,
    and the registry's intent is "what does this operator's typical
    command look like?", not "did they type it themselves?".

    Buckets (median):
    * ≤ 1  → shallow (no pipe, or one-stage pipeline)
    * == 2 → moderate
    * ≥ 3  → deep

    Confidence:
    * < ``SHELL_MASTERY_MIN_COMMANDS`` → 0.40.
    * Median within ±10% of either integer boundary (2 or 3) → 0.55.
    * Otherwise → 0.70.

    Skips emission when the session has no commands.
    """
    n = len(ctx.commands)
    if n == 0:
        return
    pipes_per_cmd = sorted(c.pipe_count for c in ctx.commands)
    median = statistics.median(pipes_per_cmd)

    if median >= PIPE_CHAINING_DEEP_MEDIAN:
        value = "deep"
    elif median >= PIPE_CHAINING_MODERATE_MEDIAN:
        value = "moderate"
    else:
        value = "shallow"

    if n < SHELL_MASTERY_MIN_COMMANDS:
        confidence = 0.40
    elif (
        _near(median, PIPE_CHAINING_MODERATE_MEDIAN)
        or _near(median, PIPE_CHAINING_DEEP_MEDIAN)
    ):
        confidence = 0.55
    else:
        confidence = 0.70

    yield make_observation(
        ctx,
        primitive="motor.shell_mastery.pipe_chaining_depth",
        value=value,
        confidence=confidence,
    )
