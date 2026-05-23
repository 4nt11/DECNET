# SPDX-License-Identifier: AGPL-3.0-or-later
"""``temporal.*`` feature functions — per-session subset.

Phase E ships the four ``temporal.*`` primitives that don't need
observation history. The other three (``session_timing``,
``persistence``, ``lifecycle_markers.idle_periodicity``) are Tier B
and computed by the attribution engine, not the extractor.

Step E.1: ``temporal.session_duration``.
Step E.2: ``temporal.escalation_pattern``.
Step E.3: ``temporal.lifecycle_markers.landing_ritual``.
Step E.4: ``temporal.lifecycle_markers.exit_behavior`` (unblocked by F.0).
"""
from __future__ import annotations

import math
import statistics
from typing import Iterator

from behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._parse import hash_token
from decnet.profiler.behave_shell._thresholds import (
    ESCALATION_BURSTY_CV,
    ESCALATION_BURSTY_ZERO_FRAC,
    ESCALATION_MIN_COMMANDS,
    ESCALATION_MIN_WINDOWS,
    ESCALATION_SUSTAINED_CV,
    ESCALATION_WINDOW_MIN_S,
    ESCALATION_WINDOW_TARGET,
    EXIT_BEHAVIOR_LOOKBACK_K,
    LANDING_RITUAL_FIRST_N,
    LANDING_RITUAL_HIT_MIN,
    LANDING_RITUAL_MIN_COMMANDS,
    SESSION_DURATION_LONG_MAX,
    SESSION_DURATION_MEDIUM_MAX,
    SESSION_DURATION_SHORT_MAX,
)


# Precomputed at import time. ``graceful`` is operator-typed shutdown;
# ``cleanup`` is the wipe-tracks vocabulary. Both expand to v0.2 once
# the corpus shows what gets missed.
_GRACEFUL_EXIT_HASHES: frozenset[str] = frozenset({
    hash_token("exit"),
    hash_token("logout"),
    hash_token("quit"),
    hash_token("logoff"),
})
_CLEANUP_TOKEN_HASHES: frozenset[str] = frozenset({
    hash_token("history"),
    hash_token("unset"),
    hash_token("rm"),
    hash_token("shred"),
    hash_token("clear"),
    hash_token("kill"),
})


# Precomputed at import time so the per-session check is a set lookup,
# not 7 sha256 ops per session. The recon-survey vocabulary an attacker
# (or scripted runner) typically opens with on a freshly-landed shell.
_LANDING_RITUAL_HASHES: frozenset[str] = frozenset({
    hash_token("uname"),
    hash_token("id"),
    hash_token("whoami"),
    hash_token("pwd"),
    hash_token("hostname"),
    hash_token("w"),
    hash_token("who"),
})


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


def landing_ritual(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``temporal.lifecycle_markers.landing_ritual`` ∈ {present, absent}.

    Inspect the first ``LANDING_RITUAL_FIRST_N`` commands; if at least
    ``LANDING_RITUAL_HIT_MIN`` of their first_token_hashes match the
    recon-survey vocabulary set (``uname`` / ``id`` / ``whoami`` /
    ``pwd`` / ``hostname`` / ``w`` / ``who``), the operator opened
    with a landing ritual.

    Skip emission when there are no commands at all — the registry's
    binary doesn't admit ``unknown`` and emitting ``absent`` from
    nothing would be dishonest. Below ``LANDING_RITUAL_MIN_COMMANDS``
    we still emit, but at lower confidence — short sessions can still
    show or fail to show a ritual.
    """
    n = len(ctx.commands)
    if n == 0:
        return
    head = ctx.commands[:LANDING_RITUAL_FIRST_N]
    hits = sum(1 for c in head if c.first_token_hash in _LANDING_RITUAL_HASHES)
    value = "present" if hits >= LANDING_RITUAL_HIT_MIN else "absent"

    if n < LANDING_RITUAL_MIN_COMMANDS:
        confidence = 0.40
    else:
        confidence = 0.65
    yield make_observation(
        ctx,
        primitive="temporal.lifecycle_markers.landing_ritual",
        value=value,
        confidence=confidence,
    )


def exit_behavior(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``temporal.lifecycle_markers.exit_behavior`` ∈ {graceful, abrupt, cleanup}.

    Resolution of the E.4 hold from Phase E. Now that F.0's
    ``Command.followed_by_prompt`` gives us prompt-after-last-command
    visibility — the exit-code proxy we couldn't get in Phase E:

    1. Last command **lacks** a trailing prompt → ``abrupt`` (session
       cut mid-output, custom PS1 swallowing, or genuinely interrupted).
    2. Last command's first_token_hash ∈ ``_GRACEFUL_EXIT_HASHES``
       (``exit`` / ``logout`` / ``quit`` / ``logoff``) → ``graceful``.
    3. Any of the last ``EXIT_BEHAVIOR_LOOKBACK_K`` (3) commands'
       first_token_hash ∈ ``_CLEANUP_TOKEN_HASHES`` (``history`` /
       ``unset`` / ``rm`` / ``shred`` / ``clear`` / ``kill``) →
       ``cleanup``.
    4. Else → ``graceful`` (clean Ctrl-D / window close).

    Skip emission when no commands.

    Confidence 0.65 when the trailing prompt is clear; 0.45 for
    ``abrupt`` (a custom PS1 suppressing prompt echo could also yield
    ``followed_by_prompt=False``).
    """
    if not ctx.commands:
        return
    last = ctx.commands[-1]
    if not last.followed_by_prompt:
        value = "abrupt"
        confidence = 0.45
    elif last.first_token_hash in _GRACEFUL_EXIT_HASHES:
        value = "graceful"
        confidence = 0.65
    else:
        tail = ctx.commands[-EXIT_BEHAVIOR_LOOKBACK_K:]
        if any(c.first_token_hash in _CLEANUP_TOKEN_HASHES for c in tail):
            value = "cleanup"
            confidence = 0.65
        else:
            value = "graceful"
            confidence = 0.65
    yield make_observation(
        ctx,
        primitive="temporal.lifecycle_markers.exit_behavior",
        value=value,
        confidence=confidence,
    )
