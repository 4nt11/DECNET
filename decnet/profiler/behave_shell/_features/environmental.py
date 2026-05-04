"""``environmental.*`` feature functions.

Phase F ships the five environmental primitives plus F.0's shared
prompt-line detector. F.0 itself emits no primitive — it populates
``SessionContext.prompt_lines`` and ``Command.followed_by_prompt``
which F.1 / F.3 / E.4 read.

Step F.1: ``environmental.shell_type``.
Step F.2: ``environmental.terminal_multiplexer``.
"""
from __future__ import annotations

import collections
from typing import Iterator

# Multiplexer fingerprints scanned over RAW output (multiplexer escapes
# ARE ANSI sequences, so we must NOT strip-ANSI before searching).
# Sources:
#   tmux DCS passthrough: ESC P tmux ;
#   tmux focus reporting: ESC [ ? 1004 (set/reset)
#   tmux window-title with explicit tmux marker
#   screen DCS:           ESC P =
#   screen-specific OSC:  ESC ] 83 ;
_TMUX_MARKERS: tuple[str, ...] = (
    "\x1bPtmux;",
    "\x1b[?1004",
    "\x1b]2;tmux",
)
_SCREEN_MARKERS: tuple[str, ...] = (
    "\x1bP=",
    "\x1b]83;",
)

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


def terminal_multiplexer(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.terminal_multiplexer`` ∈ {none, tmux, screen}.

    Scans raw output (NOT ANSI-stripped — multiplexer escapes ARE ANSI
    sequences) for tmux/screen-specific fingerprints. If both detected,
    prefer tmux (more common in 2026 nested-mux setups). Even one
    escape is conclusive — no sample-size floor.

    Confidence 0.85 when a fingerprint matches; 0.55 for ``none`` (a
    bare PTY genuinely has no multiplexer, but a hidden multiplexer
    that suppresses its escapes would also yield ``none``).

    Skip emission when the session has no commands — without operator
    interaction the engine should not emit operator-derived primitives.
    The smoke gates (``test_extract_session_empty_stream_yields_no_observations``,
    ``test_extract_session_zero_inputs_yields_nothing``) bind this:
    no commands, no observations.
    """
    if not ctx.commands:
        return
    has_tmux = False
    has_screen = False
    for _t, _k, data in ctx.output_events:
        if not has_tmux and any(m in data for m in _TMUX_MARKERS):
            has_tmux = True
        if not has_screen and any(m in data for m in _SCREEN_MARKERS):
            has_screen = True
        if has_tmux and has_screen:
            break

    if has_tmux:
        value = "tmux"
        confidence = 0.85
    elif has_screen:
        value = "screen"
        confidence = 0.85
    else:
        value = "none"
        confidence = 0.55
    yield make_observation(
        ctx,
        primitive="environmental.terminal_multiplexer",
        value=value,
        confidence=confidence,
    )
