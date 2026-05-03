"""``cognitive.*`` feature functions.

Step 5: ``cognitive.inter_command_latency_class``.
Step 6: ``cognitive.command_branch_diversity``.
Step 7: ``cognitive.feedback_loop_engagement``.
Step 8: ``cognitive.inter_command_consistency``.
"""
from __future__ import annotations

import statistics
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._thresholds import (
    BRANCH_DIVERSITY_LINEAR_MIN,
    FEEDBACK_CORRELATION_MIN,
    FEEDBACK_MIN_PAIRS,
    INTER_CMD_DELIBERATE_MAX,
    INTER_CMD_INSTANT_MAX,
    INTER_CMD_LLM_HEAVYWEIGHT_MAX,
    INTER_CMD_LLM_LIGHTWEIGHT_MAX,
    INTER_CMD_TYPING_MAX,
    MIN_COMMANDS_FOR_FULL_CONFIDENCE,
)


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
