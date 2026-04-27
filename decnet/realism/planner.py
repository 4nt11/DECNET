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
from decnet.realism.taxonomy import ContentClass, Plan, PlanAction  # noqa: F401


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
    edit_candidate: Optional[dict[str, Any]] = None,
    rand: Optional[secrets.SystemRandom] = None,
) -> Optional[Plan]:
    """Return a single :class:`Plan` for the orchestrator's tick.

    Stage-3b policy: weighted action roll — 60% create, 30% edit, 10%
    "leave alone" (planner returns ``None`` to skip).  When the roll
    is "edit" and *edit_candidate* is set (a row from
    :meth:`BaseRepository.pick_random_synthetic_file_for_edit`), we
    return an edit Plan; otherwise we fall through to create.

    The orchestrator scheduler is responsible for fetching the edit
    candidate before calling — keeps this function pure-of-DB and
    test-friendly.

    Returns ``None`` when no eligible (decky, persona) pair exists or
    when the action roll lands on "leave alone."
    """
    rng = rand or secrets.SystemRandom()

    eligible = _eligible_pairs(deckies, now)
    if not eligible:
        return None

    # Action roll.  Edit only fires when there's a candidate from the
    # repo — otherwise we either re-roll to create or skip.
    roll = rng.random()
    if roll < 0.10:
        return None  # "leave alone" — quiet tick is realism too
    if roll < 0.40 and edit_candidate is not None:
        return _edit_plan(edit_candidate, now, rng)

    decky, persona = rng.choice(eligible)

    # User vs system content — biased toward user (realism wins are
    # bigger there).
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


def _edit_plan(
    candidate: dict[str, Any],
    now: datetime,
    rng: secrets.SystemRandom,
) -> Optional[Plan]:
    """Build an edit-action :class:`Plan` from a synthetic_files row.

    The candidate dict is the shape :meth:`BaseRepository.list_synthetic_files`
    returns — we only need ``decky_uuid``, ``path``, ``persona``,
    ``content_class``, ``last_body``, ``uuid``.  Returns ``None`` if
    the candidate's content_class is somehow not editable (defensive
    — the repo query already filters those out).
    """
    try:
        cls = ContentClass(candidate["content_class"])
    except (KeyError, ValueError):
        return None
    if cls.is_canary() or cls == ContentClass.CACHE_TMP:
        return None
    # mtime: edits bump forward by ~hours-to-days, but never past now.
    # We model as "the file was edited some time after creation but
    # before now" — sample_mtime with a tighter cap keeps it recent.
    edit_mtime = sample_mtime(
        "00:00-00:00", now, rand=rng,
        backdate_min_hours=1.0, backdate_max_days=2.0,
    )
    return Plan(
        decky_uuid=candidate["decky_uuid"],
        decky_name=candidate.get("decky_name", ""),
        persona=candidate.get("persona", ""),
        content_class=cls,
        action="edit",
        target_path=candidate["path"],
        mtime=edit_mtime,
        body_hint=None,  # edit uses previous_body, not a fresh hint
        previous_body=candidate.get("last_body", ""),
        notes=(
            f"persona={candidate.get('persona', '')}",
            f"class={cls.value}",
            "action=edit",
            f"synthetic_file_uuid={candidate.get('uuid', '')}",
        ),
    )
