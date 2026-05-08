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
from decnet.profiler.behave_shell._intent import classify_intent
from decnet.profiler.behave_shell._thresholds import (
    INTENT_FULL_CONFIDENCE_MIN,
    INTENT_MIN_COMMANDS,
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
