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
