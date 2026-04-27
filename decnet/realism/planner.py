"""Realism planner — picks the next ``(decky, persona, class, action)`` tuple.

Stage-1 stub: the public signature is in place so the orchestrator
worker (stage 3) can import it, but the body returns ``None`` ("nothing
to do this tick") until stage 3 wires the synthetic_files table and
naming/body generators.

The eventual policy lives entirely in :func:`pick`; downstream
consumers should not branch on ``ContentClass`` themselves — let the
planner decide weights and rate-limits in one place.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any, Optional, Sequence

from decnet.realism.taxonomy import Plan


def pick(
    deckies: Sequence[dict[str, Any]],
    now: datetime,
    *,
    repo: Any = None,
    rand: Optional[secrets.SystemRandom] = None,
) -> Optional[Plan]:
    """Return the next :class:`Plan` for the orchestrator's tick.

    Stage-1 stub returns ``None`` unconditionally so the orchestrator
    can import this function before the real implementation lands.  The
    full policy (diurnal gate, action distribution 60/30/10
    create/edit/leave, content-class weights, canary rate-limit) lands
    in stage 3 of the realism migration.

    Parameters
    ----------
    deckies :
        Output of :meth:`BaseRepository.list_running_deckies`.  Each
        entry must carry ``uuid``, ``name``, ``services``,
        ``email_personas`` (topology-pool JSON or list).
    now :
        Tick timestamp.  Injected so tests don't need to monkey-patch
        :func:`datetime.utcnow`.
    repo :
        :class:`BaseRepository` for synthetic_files lookup (edit
        action).  Optional in stage 1; required from stage 3 onward.
    rand :
        RNG for sampling.  Defaults to a fresh
        :class:`secrets.SystemRandom`.
    """
    _ = (deckies, now, repo, rand)  # silence unused-arg until stage 3
    return None
