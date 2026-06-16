# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared state-modulation helpers for rule consumers.

Both :class:`~decnet.ttp.impl.rule_engine.RuleEngine` and the per-source
lifters (E.3.9 onward) read :class:`~decnet.ttp.store.base.RuleState`
the same way: skip on ``disabled``, defense-in-depth re-check
``expires_at``, clamp confidence on ``clipped``. Single source of truth
so a future change to the state contract lands in one place.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decnet.ttp.store.base import RuleState


def is_active(state: "RuleState") -> bool:
    """Return ``True`` iff a rule with this state is allowed to fire.

    ``disabled`` rules never fire. ``clipped`` rules still fire — the
    clip caps emitted confidence, doesn't suppress the emit. Expired
    states act as ``disabled`` even though the store auto-reverts; the
    re-check here is defense-in-depth against a racing read between
    expiry and the store's revert pass.
    """
    if state.state == "disabled":
        return False
    if state.expires_at is not None:
        expires = state.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(tz=timezone.utc):
            return False
    return True


def apply_ceiling(base: float, state: "RuleState") -> float:
    """Apply the operator's confidence ceiling, downward only.

    A ``clipped`` state with ``confidence_max < 1.0`` clamps the emitted
    confidence to ``min(base, ceiling)``. Any other state is a
    no-op. The clamp is downward by construction — operator clips can
    never raise a rule's confidence above its YAML-declared base, per
    TTP_TAGGING.md §"Confidence model".
    """
    if state.state != "clipped":
        return base
    ceiling = state.confidence_max
    if ceiling is None or ceiling >= 1.0:
        return base
    return min(base, ceiling)


__all__ = ["is_active", "apply_ceiling"]
