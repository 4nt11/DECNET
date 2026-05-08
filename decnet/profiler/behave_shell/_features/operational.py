"""``operational.*`` feature functions (Phase G).

Step G.1: ``operational.objective``.
Step G.2: ``operational.opsec_discipline`` (lands later).
Step G.3: ``operational.cleanup_behavior`` (lands later).
Step G.4: ``operational.multi_actor_indicators`` (lands later).
"""
from __future__ import annotations

import collections
from typing import Iterator

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._features.temporal import (
    _CLEANUP_TOKEN_HASHES,
)
from decnet.profiler.behave_shell._intent import (
    OPSEC_HISTORY_TOKENS,
    classify_intent,
)
from decnet.profiler.behave_shell._thresholds import (
    EXIT_BEHAVIOR_LOOKBACK_K,
    INTENT_FULL_CONFIDENCE_MIN,
    INTENT_MIN_COMMANDS,
    MIN_COMMANDS_FOR_FULL_CONFIDENCE,
)


def objective(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``operational.objective`` ∈ {recon, exfil, persistence,
    lateral, destructive}.

    Walk every command's ``first_token_hash`` through
    :func:`classify_intent` (fixed precedence:
    ``destructive > persistence > exfil > lateral > recon``).
    Commands that don't classify (token not in any set) are skipped —
    the registry has no ``unknown`` value here, so a session of pure
    ``vim`` / ``ls`` operations is allowed to fall through and emit
    ``recon`` only if at least :data:`INTENT_MIN_COMMANDS` commands
    actually classify.

    Skip emission when fewer than ``INTENT_MIN_COMMANDS`` classified
    hits — too thin to call. Otherwise majority vote (ties broken by
    precedence order via ``most_common(1)``-stable sort over the
    insertion order, which mirrors the precedence walk).

    Confidence: 0.40 below :data:`INTENT_FULL_CONFIDENCE_MIN`; 0.60
    above. v0.1 lexicon — corpus tuning revisits in v0.2.
    """
    if not ctx.commands:
        return
    counter: collections.Counter[str] = collections.Counter()
    for cmd in ctx.commands:
        label = classify_intent(cmd.first_token_hash)
        if label is not None:
            counter[label] += 1
    n_classified = sum(counter.values())
    if n_classified < INTENT_MIN_COMMANDS:
        return
    value = counter.most_common(1)[0][0]
    confidence = 0.60 if n_classified >= INTENT_FULL_CONFIDENCE_MIN else 0.40
    yield make_observation(
        ctx,
        primitive="operational.objective",
        value=value,
        confidence=confidence,
    )


def opsec_discipline(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``operational.opsec_discipline`` ∈ {careful, careless, learning}.

    * ``careful`` — operator hits ``OPSEC_HISTORY_TOKENS`` AND the
      tail-K (=``EXIT_BEHAVIOR_LOOKBACK_K``) commands include cleanup
      vocabulary (locally re-derived; we do **not** read prior
      observations).
    * ``learning`` — operator hits ``OPSEC_HISTORY_TOKENS`` but does
      NOT close with cleanup tokens. Half-discipline.
    * ``careless`` — no ``OPSEC_HISTORY_TOKENS`` hits at all.

    Skip emission when no commands. Confidence 0.45 (small lexicon,
    soft); 0.30 below ``MIN_COMMANDS_FOR_FULL_CONFIDENCE`` (=5).
    """
    if not ctx.commands:
        return
    has_history = any(
        c.first_token_hash in OPSEC_HISTORY_TOKENS for c in ctx.commands
    )
    tail = ctx.commands[-EXIT_BEHAVIOR_LOOKBACK_K:]
    has_cleanup_tail = any(
        c.first_token_hash in _CLEANUP_TOKEN_HASHES for c in tail
    )
    if not has_history:
        value = "careless"
    elif has_cleanup_tail:
        value = "careful"
    else:
        value = "learning"
    if len(ctx.commands) < MIN_COMMANDS_FOR_FULL_CONFIDENCE:
        confidence = 0.30
    else:
        confidence = 0.45
    yield make_observation(
        ctx,
        primitive="operational.opsec_discipline",
        value=value,
        confidence=confidence,
    )
