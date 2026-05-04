"""``environmental.*`` feature functions.

Phase F ships the five environmental primitives plus F.0's shared
prompt-line detector. F.0 itself emits no primitive — it populates
``SessionContext.prompt_lines`` and ``Command.followed_by_prompt``
which F.1 / F.3 / E.4 read.

Step F.1: ``environmental.shell_type``.
"""
from __future__ import annotations

import collections
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._parse import PromptLine
from decnet.profiler.behave_shell._thresholds import (
    SHELL_TYPE_MIN_PROMPTS,
)


def _classify_shell_from_prompt(p: PromptLine) -> str:
    """Map one prompt line to a shell-type label."""
    suffix = p.suffix_char
    line = p.raw_line
    if suffix in ("$", "#"):
        # bash / sh / dash all share these — collapsed to "bash" per
        # registry's bash-family stance. zsh CAN be configured to use
        # $/# but that's the user's PS1 override; default zsh is %.
        return "bash"
    if suffix == "%":
        return "zsh"
    if suffix == ">":
        # Disambiguate by line content. powershell's PS1 starts with
        # "PS "; cmd.exe's prompt typically contains a Windows path
        # like "C:\". Everything else is fish.
        if line.lstrip().startswith("PS "):
            return "powershell"
        if "C:\\" in line or "c:\\" in line:
            return "cmd.exe"
        return "fish"
    return "bash"  # defensive — _detect_prompt_suffix only emits one of $#%>


def shell_type(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.shell_type``.

    Mode of per-prompt-line classification across
    ``ctx.prompt_lines``. Skip emission when no prompts detected —
    the registry's enum doesn't admit ``unknown`` and emitting
    ``bash`` from no observation at all would be dishonest.

    Confidence drops below ``SHELL_TYPE_MIN_PROMPTS`` (3 prompts);
    above that threshold the vote is solid.
    """
    if not ctx.prompt_lines:
        return
    votes = collections.Counter(
        _classify_shell_from_prompt(p) for p in ctx.prompt_lines
    )
    value, _ = votes.most_common(1)[0]

    if len(ctx.prompt_lines) < SHELL_TYPE_MIN_PROMPTS:
        confidence = 0.40
    else:
        confidence = 0.75
    yield make_observation(
        ctx,
        primitive="environmental.shell_type",
        value=value,
        confidence=confidence,
    )
