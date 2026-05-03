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
    command_branch_diversity,
    feedback_loop_engagement,
    inter_command_latency_class,
)
from decnet.profiler.behave_shell._features.motor import (
    input_modality,
    paste_burst_rate,
)

FeatureFn = Callable[[SessionContext], Iterable[Observation]]

FEATURES: tuple[FeatureFn, ...] = (
    input_modality,
    paste_burst_rate,
    inter_command_latency_class,
    command_branch_diversity,
    feedback_loop_engagement,
)
