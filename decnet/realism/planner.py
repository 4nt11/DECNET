"""Realism planner — picks the next ``(decky, persona, class, action)`` tuple.

Stage 3: returns ``create``-only plans (the edit branch lands in
stage 3b).  Pure-function, deterministic given the same inputs:
caller passes deckies (with personas pre-resolved on each row),
``now``, and an RNG.

The persona resolution split — topology-pool vs. global-pool — is
the orchestrator's job, not the planner's.  Each decky dict reaching
:func:`pick` carries a ``_realism_personas`` key with the resolved
:class:`~decnet.realism.personas.EmailPersona` list.  Keeps the
planner test-isolated and avoids forcing it to know about the
:class:`~decnet.web.db.repository.BaseRepository` / topology pool /
global pool.

Diurnal gating uses :func:`decnet.realism.diurnal.in_work_hours` per
persona; we filter the (decky, persona) pairs *before* picking, so a
persona outside its window is never considered.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any, Optional, Sequence

from decnet.realism import bodies, naming
from decnet.realism.diurnal import in_work_hours, sample_mtime
from decnet.realism.personas import EmailPersona
from decnet.realism.taxonomy import ContentClass, Plan


# Stage-3 weighted sampling:
#   * User content (notes/todo/draft/script) gets the bulk — those are
#     the realism win when a persona "looks busy."
#   * System content (cron/daemon/cache) is plausible filler.
#   * Email + canary are owned by other paths and not picked here.
_USER_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = (
    (ContentClass.NOTE, 30),
    (ContentClass.TODO, 20),
    (ContentClass.DRAFT, 15),
    (ContentClass.SCRIPT, 10),
)
_SYSTEM_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = (
    (ContentClass.LOG_CRON, 12),
    (ContentClass.LOG_DAEMON, 8),
    (ContentClass.CACHE_TMP, 5),
)


def _weighted_pick(
    weights: tuple[tuple[ContentClass, int], ...],
    rng: secrets.SystemRandom,
) -> ContentClass:
    total = sum(w for _, w in weights)
    target = rng.randint(1, total)
    running = 0
    for cls, w in weights:
        running += w
        if target <= running:
            return cls
    return weights[-1][0]  # unreachable, satisfy mypy


def _eligible_pairs(
    deckies: Sequence[dict[str, Any]],
    now: datetime,
) -> list[tuple[dict[str, Any], EmailPersona]]:
    """Cross-product of deckies × resolved personas, diurnal-filtered.

    A decky with no personas (empty ``_realism_personas``) is skipped
    entirely; same fail-quiet semantics as the emailgen scheduler.
    """
    out: list[tuple[dict[str, Any], EmailPersona]] = []
    for decky in deckies:
        personas: list[EmailPersona] = decky.get("_realism_personas") or []
        for persona in personas:
            if in_work_hours(persona.active_hours, now):
                out.append((decky, persona))
    return out


def pick(
    deckies: Sequence[dict[str, Any]],
    now: datetime,
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> Optional[Plan]:
    """Return a single :class:`Plan` for the orchestrator's tick.

    Stage-3 policy: create-only.  Stage 3b extends with the
    create/edit/leave roll and the synthetic_files lookup for edits.

    Returns ``None`` when no eligible (decky, persona) pair exists —
    the orchestrator treats that as "skip this tick" the same way the
    pre-realism scheduler did.
    """
    rng = rand or secrets.SystemRandom()

    eligible = _eligible_pairs(deckies, now)
    if not eligible:
        return None

    decky, persona = rng.choice(eligible)

    # User vs system content — biased toward user (realism wins are
    # bigger there).  Once stage 3b ships edit-in-place, the edit
    # branch will reuse the same content_class as the existing row;
    # the create branch picks fresh here.
    if rng.random() < 0.7:
        content_class = _weighted_pick(_USER_CLASS_WEIGHTS, rng)
    else:
        content_class = _weighted_pick(_SYSTEM_CLASS_WEIGHTS, rng)

    target_path = naming.make_path(content_class, persona.name, rand=rng)
    body_hint = bodies.make_body(content_class, persona.name, rand=rng)
    mtime = sample_mtime(persona.active_hours, now, rand=rng)

    return Plan(
        decky_uuid=decky["uuid"],
        decky_name=decky["name"],
        persona=persona.name,
        content_class=content_class,
        action="create",
        target_path=target_path,
        mtime=mtime,
        body_hint=body_hint,
        notes=(
            f"persona={persona.name}",
            f"class={content_class.value}",
            f"window={persona.active_hours}",
        ),
    )
