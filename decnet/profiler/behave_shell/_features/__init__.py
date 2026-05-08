"""Registered feature functions.

Each entry takes a ``SessionContext`` and yields zero or more
``Observation`` instances. Adding a primitive = adding a function in a
sibling module and appending it to ``FEATURES``.
"""
from __future__ import annotations

from typing import Callable, Iterable

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features.cognitive import (
    cognitive_load,
    command_branch_diversity,
    error_resilience_fallback_to_man,
    error_resilience_frustration_typing,
    error_resilience_retry_tactic,
    exploration_style,
    feedback_loop_engagement,
    planning_depth,
    tool_vocabulary,
    inter_command_consistency,
    inter_command_latency_class,
)
from decnet.profiler.behave_shell._features.emotional_valence import (
    arousal,
    valence,
)
from decnet.profiler.behave_shell._features.environmental import (
    keyboard_layout,
    locale,
    numpad_usage,
    shell_type,
    terminal_multiplexer,
)
from decnet.profiler.behave_shell._features.operational import (
    cleanup_behavior,
    multi_actor_indicators,
    objective,
    opsec_discipline,
)
from decnet.profiler.behave_shell._features.temporal import (
    escalation_pattern,
    exit_behavior,
    landing_ritual,
    session_duration,
)
from decnet.profiler.behave_shell._features.motor import (
    command_chunking,
    error_correction,
    input_modality,
    keystroke_cadence,
    motor_stability,
    paste_burst_rate,
    pipe_chaining_depth,
    shortcut_usage,
    tab_completion,
)

FeatureFn = Callable[[SessionContext], Iterable[Observation]]

FEATURES: tuple[FeatureFn, ...] = (
    input_modality,
    paste_burst_rate,
    keystroke_cadence,
    motor_stability,
    error_correction,
    command_chunking,
    tab_completion,
    shortcut_usage,
    pipe_chaining_depth,
    inter_command_latency_class,
    command_branch_diversity,
    feedback_loop_engagement,
    inter_command_consistency,
    cognitive_load,
    exploration_style,
    planning_depth,
    tool_vocabulary,
    error_resilience_retry_tactic,
    error_resilience_frustration_typing,
    error_resilience_fallback_to_man,
    session_duration,
    escalation_pattern,
    landing_ritual,
    exit_behavior,
    shell_type,
    terminal_multiplexer,
    locale,
    keyboard_layout,
    numpad_usage,
    objective,
    opsec_discipline,
    cleanup_behavior,
    multi_actor_indicators,
    valence,
    arousal,
)
