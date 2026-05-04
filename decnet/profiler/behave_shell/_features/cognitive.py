"""``cognitive.*`` feature functions.

Step 5: ``cognitive.inter_command_latency_class``.
Step 6: ``cognitive.command_branch_diversity``.
Step 7: ``cognitive.feedback_loop_engagement``.
Step 8: ``cognitive.inter_command_consistency``.
Step D.1: ``cognitive.cognitive_load``.
"""
from __future__ import annotations

import statistics
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    BRANCH_DIVERSITY_LINEAR_MIN,
    COGNITIVE_LOAD_CHUNKING_REF_CV,
    COGNITIVE_LOAD_LOW_MAX,
    COGNITIVE_LOAD_MEDIUM_MAX,
    COGNITIVE_LOAD_PACE_REF_CV,
    EXPLORATION_CHAOTIC_BACKTRACK_MIN,
    EXPLORATION_TARGETED_REP_MIN,
    FEEDBACK_CORRELATION_MIN,
    FEEDBACK_MIN_PAIRS,
    INTER_CMD_DELIBERATE_MAX,
    INTER_CMD_INSTANT_MAX,
    INTER_CMD_LLM_HEAVYWEIGHT_MAX,
    INTER_CMD_LLM_LIGHTWEIGHT_MAX,
    INTER_CMD_TYPING_MAX,
    MIN_COMMANDS_FOR_FULL_CONFIDENCE,
    PAUSE_CV_BIMODAL_MIN,
    PAUSE_CV_METRONOMIC_MAX,
)


def _clip01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _cv(xs: tuple[float, ...] | list[float]) -> float | None:
    """Coefficient of variation; ``None`` if undefined (n<2 or mean==0)."""
    if len(xs) < 2:
        return None
    mean = statistics.fmean(xs)
    if mean <= 0.0:
        return None
    return statistics.stdev(xs) / mean


def _bucket_inter_cmd_latency(median_iat: float) -> str:
    if median_iat <= INTER_CMD_INSTANT_MAX:
        return "instant"
    if median_iat <= INTER_CMD_TYPING_MAX:
        return "typing_speed"
    if median_iat <= INTER_CMD_DELIBERATE_MAX:
        return "deliberate"
    if median_iat <= INTER_CMD_LLM_LIGHTWEIGHT_MAX:
        return "llm_lightweight"
    if median_iat <= INTER_CMD_LLM_HEAVYWEIGHT_MAX:
        return "llm_heavyweight"
    return "long"


def inter_command_latency_class(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``cognitive.inter_command_latency_class``.

    Operator's *thinking pace* between commands, bucketed against
    calibrated thresholds. Splits LW-sim / CLAUDE-FF / CLAUDE-CL.
    """
    if not ctx.inter_cmd_iats:
        return
    median_iat = statistics.median(ctx.inter_cmd_iats)
    bucket = _bucket_inter_cmd_latency(median_iat)
    # Sample-size honesty: < 5 commands → halve confidence
    if len(ctx.commands) < MIN_COMMANDS_FOR_FULL_CONFIDENCE:
        confidence = 0.40
    else:
        confidence = 0.80
    yield make_observation(
        ctx,
        primitive="cognitive.inter_command_latency_class",
        value=bucket,
        confidence=confidence,
    )


def command_branch_diversity(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``cognitive.command_branch_diversity``.

    Content-based discriminator (no timing): unique first-token ratio
    over total commands. Splits CLAUDE-FF (linear_playbook) from
    CLAUDE-CL (adaptive_branching). The empirical anchor on
    2026-05-02: fire-and-forget runs ~10 distinct tools; closed-loop
    runs 5-6 with ``curl`` re-invoked as the operator chases threads.
    """
    n = len(ctx.commands)
    if n == 0:
        # No commands at all → nothing honest to say. Skip emission.
        return
    if n < MIN_COMMANDS_FOR_FULL_CONFIDENCE:
        # Registry admits "unknown"; absence of *enough* data is itself
        # a high-confidence answer.
        yield make_observation(
            ctx,
            primitive="cognitive.command_branch_diversity",
            value="unknown",
            confidence=1.0,
        )
        return
    unique = len({c.first_token_hash for c in ctx.commands})
    ratio = unique / n
    if ratio >= BRANCH_DIVERSITY_LINEAR_MIN:
        value = "linear_playbook"
    else:
        # Anything below the linear floor is treated as adaptive — the
        # operator is reusing tools, the discriminative signal we
        # actually want.
        value = "adaptive_branching"
    yield make_observation(
        ctx,
        primitive="cognitive.command_branch_diversity",
        value=value,
        confidence=0.80,
    )


def feedback_loop_engagement(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``cognitive.feedback_loop_engagement``.

    Pearson correlation between ``output_per_cmd[i]`` (bytes the
    operator saw before the next command) and
    ``inter_cmd_iats[i]`` (the pause that followed). closed_loop
    operators read more before pausing more; fire_and_forget operators
    pace independently of output. CUTS ACROSS the LLM/human axis —
    closed-loop LLMs and reading humans both score closed_loop.

    First primitive that depends on output events: zero output events
    in the shard → emit ``unknown`` at confidence 1.0 (no honest
    correlation possible) and exit.
    """
    pairs = list(zip(ctx.output_per_cmd, ctx.inter_cmd_iats))
    if not ctx.output_events or len(pairs) < FEEDBACK_MIN_PAIRS:
        if not ctx.commands:
            return
        yield make_observation(
            ctx,
            primitive="cognitive.feedback_loop_engagement",
            value="unknown",
            confidence=1.0,
        )
        return
    xs = [float(p[0]) for p in pairs]
    ys = [float(p[1]) for p in pairs]
    try:
        r = statistics.correlation(xs, ys)
    except statistics.StatisticsError:
        # Constant series on either axis — correlation undefined.
        yield make_observation(
            ctx,
            primitive="cognitive.feedback_loop_engagement",
            value="unknown",
            confidence=1.0,
        )
        return
    if r > FEEDBACK_CORRELATION_MIN:
        value = "closed_loop"
    else:
        value = "fire_and_forget"
    yield make_observation(
        ctx,
        primitive="cognitive.feedback_loop_engagement",
        value=value,
        confidence=0.75,
    )


def exploration_style(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``cognitive.exploration_style`` ∈ {methodical, chaotic, targeted}.

    Two-axis classification over the first_token_hash sequence:

    * **methodical** — low repetition, low backtracks. Operator marches
      forward through new tools.
    * **targeted** — high repetition (R ≥ EXPLORATION_TARGETED_REP_MIN).
      Same tool re-invoked repeatedly; the operator is drilling.
    * **chaotic** — high backtrack rate (J ≥ EXPLORATION_CHAOTIC_BACKTRACK_MIN).
      Jumps among previously-used tools without a clear thread.

    The registry doesn't permit ``unknown``; below the
    MIN_COMMANDS_FOR_FULL_CONFIDENCE floor we emit at confidence 0.40
    rather than skip — the engine has *some* signal, just less of it.
    Skip emission only when there are no commands at all.
    """
    n = len(ctx.commands)
    if n == 0:
        return
    hashes = [c.first_token_hash for c in ctx.commands]
    unique = len(set(hashes))
    repetition_rate = 0.0 if n == 0 else 1.0 - (unique / n)

    # Backtrack: at position i, hashes[i] previously seen at index < i-1
    # and not equal to hashes[i-1]. (Repeating the immediate predecessor
    # is "drilling", picked up by repetition_rate; backtrack is the
    # non-local jump signal.)
    seen_before: set[str] = set()
    backtracks = 0
    transitions = 0
    if hashes:
        seen_before.add(hashes[0])
    for i in range(1, n):
        transitions += 1
        if hashes[i] != hashes[i - 1] and hashes[i] in seen_before:
            backtracks += 1
        seen_before.add(hashes[i])
    backtrack_rate = (backtracks / transitions) if transitions else 0.0

    if backtrack_rate >= EXPLORATION_CHAOTIC_BACKTRACK_MIN:
        value = "chaotic"
    elif repetition_rate >= EXPLORATION_TARGETED_REP_MIN:
        value = "targeted"
    else:
        value = "methodical"

    if n < MIN_COMMANDS_FOR_FULL_CONFIDENCE:
        confidence = 0.40
    else:
        confidence = 0.60
    yield make_observation(
        ctx,
        primitive="cognitive.exploration_style",
        value=value,
        confidence=confidence,
    )


def cognitive_load(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``cognitive.cognitive_load`` ∈ {low, medium, high}.

    Composite of three [0, 1]-clipped sub-signals, mean-aggregated:

    * **chunking** — median CV of intra-command IATs / reference CV.
      Fragmented mid-command typing → high contribution.
    * **errors** — fraction of commands whose post-execution output
      matched a canonical error fingerprint (``Command.errored`` from
      Step D.0). Failures pile load.
    * **pace variability** — CV of inter-command IATs / reference CV.
      A spread of think-pause durations → unsettled cadence → load.

    Components missing data contribute 0.0 (no penalty for an absent
    signal), and the composite normalises by *available* component
    count so a session with zero inter-command pauses isn't punished
    for the silence. Skip emission entirely when no commands at all
    exist — there's no honest answer.

    v0.1 thresholds; D.8 re-tunes once the rest of Phase D is stable.
    """
    if not ctx.commands:
        return

    # Component A: chunking variance — median within-command CV
    per_cmd_cvs: list[float] = []
    for cmd_iats in ctx.intra_command_iats:
        cv = _cv(cmd_iats)
        if cv is not None:
            per_cmd_cvs.append(cv)
    if per_cmd_cvs:
        chunking_load: float | None = _clip01(
            statistics.median(per_cmd_cvs) / COGNITIVE_LOAD_CHUNKING_REF_CV
        )
    else:
        chunking_load = None

    # Component B: error rate
    error_load: float = sum(1 for c in ctx.commands if c.errored) / len(ctx.commands)
    error_load = _clip01(error_load)

    # Component C: pace variability — CV of inter-command IATs
    pace_cv = _cv(ctx.inter_cmd_iats)
    if pace_cv is not None:
        pace_load: float | None = _clip01(pace_cv / COGNITIVE_LOAD_PACE_REF_CV)
    else:
        pace_load = None

    components = [c for c in (chunking_load, error_load, pace_load) if c is not None]
    if not components:
        return
    load = sum(components) / len(components)

    if load < COGNITIVE_LOAD_LOW_MAX:
        value = "low"
    elif load < COGNITIVE_LOAD_MEDIUM_MAX:
        value = "medium"
    else:
        value = "high"

    if len(ctx.commands) < MIN_COMMANDS_FOR_FULL_CONFIDENCE:
        confidence = 0.40
    else:
        # Composite over three soft sub-signals — held below the
        # cap of single-source primitives. D.8 re-tunes.
        confidence = 0.60
    yield make_observation(
        ctx,
        primitive="cognitive.cognitive_load",
        value=value,
        confidence=confidence,
    )


def inter_command_consistency(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``cognitive.inter_command_consistency``.

    CV (stdev / mean) of inter-command IATs.

    * ``metronomic`` (CV < 0.40) → LLM-pure. Empirical anchor:
      LLM-simulated session CV ≈ 0.24 in this corpus.
    * ``variable`` (0.40 ≤ CV < 1.50) → human. Empirical anchor:
      human session CV ≈ 0.94.
    * ``bimodal`` (CV ≥ 1.50) → LLM-assisted human, heuristic. v0.1
      uses CV-only; true bimodal detection (Hartigan dip / two-peak)
      is filed for v0.2 per the registry's ``notes:`` field.
    """
    iats = ctx.inter_cmd_iats
    if len(iats) < 2:
        return
    mean = statistics.fmean(iats)
    if mean <= 0.0:
        return
    cv = statistics.stdev(iats) / mean
    if cv < PAUSE_CV_METRONOMIC_MAX:
        value = "metronomic"
    elif cv >= PAUSE_CV_BIMODAL_MIN:
        value = "bimodal"
    else:
        value = "variable"
    confidence = (
        0.40 if len(ctx.commands) < MIN_COMMANDS_FOR_FULL_CONFIDENCE else 0.75
    )
    yield make_observation(
        ctx,
        primitive="cognitive.inter_command_consistency",
        value=value,
        confidence=confidence,
    )
