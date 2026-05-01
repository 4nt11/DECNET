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
import threading
from datetime import datetime
from typing import Any, Optional, Sequence

from decnet.realism import bodies, naming
from decnet.realism.diurnal import in_work_hours, sample_mtime
from decnet.realism.personas import EmailPersona
from decnet.realism.taxonomy import ContentClass, Plan, PlanAction  # noqa: F401


# Stage-3 weighted sampling defaults:
#   * User content (notes/todo/draft/script) gets the bulk — those are
#     the realism win when a persona "looks busy."
#   * System content (cron/daemon/cache) is plausible filler.
#   * Email + canary are owned by other paths and not picked here.
#   * Canary classes are picked rarely. Each plant materialises a real
#     CanaryToken row + DNS slug + HTTP URL — flooding the fleet makes
#     the dashboard noisy. ~3% of file picks land here.
#
# These are the *defaults*. Operator-tuned overrides arrive via
# :func:`apply_payload` (admin PUT /api/v1/realism/config). The
# orchestrator worker periodically refreshes the in-process state from
# the ``realism_config`` table; pick() reads the live globals each call.
_DEFAULT_USER_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = (
    (ContentClass.NOTE, 30),
    (ContentClass.TODO, 20),
    (ContentClass.DRAFT, 15),
    (ContentClass.SCRIPT, 10),
)
_DEFAULT_SYSTEM_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = (
    (ContentClass.LOG_CRON, 12),
    (ContentClass.LOG_DAEMON, 8),
    (ContentClass.CACHE_TMP, 5),
)
_DEFAULT_CANARY_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = (
    (ContentClass.CANARY_AWS_CREDS, 1),
    (ContentClass.CANARY_ENV_FILE, 1),
    (ContentClass.CANARY_GIT_CONFIG, 1),
    (ContentClass.CANARY_SSH_KEY, 1),
    (ContentClass.CANARY_HONEYDOC, 1),
    (ContentClass.CANARY_HONEYDOC_DOCX, 1),
    (ContentClass.CANARY_HONEYDOC_PDF, 1),
    (ContentClass.CANARY_MYSQL_DUMP, 1),
    (ContentClass.CANARY_FINGERPRINT_HTML, 1),
    (ContentClass.CANARY_FINGERPRINT_SVG, 1),
)
_DEFAULT_CANARY_PROBABILITY = 0.03

# Live (mutable) globals — reassigned by :func:`apply_payload`. pick()
# reads these. Reset to defaults via :func:`reset_to_defaults` (used by
# tests + the API DELETE path).
_USER_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = _DEFAULT_USER_CLASS_WEIGHTS
_SYSTEM_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = _DEFAULT_SYSTEM_CLASS_WEIGHTS
_CANARY_CLASS_WEIGHTS: tuple[tuple[ContentClass, int], ...] = _DEFAULT_CANARY_CLASS_WEIGHTS
_CANARY_PROBABILITY: float = _DEFAULT_CANARY_PROBABILITY
_planner_lock = threading.Lock()


def _serialize_weights(
    weights: tuple[tuple[ContentClass, int], ...],
) -> list[dict[str, Any]]:
    return [{"content_class": cls.value, "weight": w} for cls, w in weights]


def _parse_weights(
    raw: Any, allowed: set[ContentClass],
) -> tuple[tuple[tuple[ContentClass, int], ...], list[str]]:
    """Parse ``[{"content_class": "...", "weight": N}, ...]`` into the
    planner's internal tuple shape.

    Returns ``(weights, dropped)`` where *dropped* is the list of
    ``content_class`` values that were valid enum members but not in
    *allowed* (e.g. a canary class pasted onto the user list). Callers
    surface *dropped* in the API response so the operator can see the
    entry didn't land without having to re-read the config.

    Raises ``ValueError`` on structural problems (non-list, non-int
    weight, negative weight, empty result) so the API can return 400.
    """
    if not isinstance(raw, list):
        raise ValueError("weights must be a list")
    out: list[tuple[ContentClass, int]] = []
    dropped: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("each weight entry must be an object")
        cls_name = entry.get("content_class")
        weight = entry.get("weight")
        if not isinstance(weight, int) or weight < 0:
            raise ValueError(
                f"weight for {cls_name!r} must be a non-negative integer"
            )
        try:
            cls = ContentClass(cls_name)
        except (ValueError, TypeError):
            raise ValueError(f"unknown content_class: {cls_name!r}")
        if cls not in allowed:
            dropped.append(cls.value)
            continue
        out.append((cls, weight))
    if not out:
        raise ValueError("weights list resolved to zero valid entries")
    if sum(w for _, w in out) <= 0:
        raise ValueError("weights must sum to a positive number")
    return tuple(out), dropped


_USER_CLASSES: set[ContentClass] = {
    ContentClass.NOTE, ContentClass.TODO, ContentClass.DRAFT, ContentClass.SCRIPT,
}
_SYSTEM_CLASSES: set[ContentClass] = {
    ContentClass.LOG_CRON, ContentClass.LOG_DAEMON, ContentClass.CACHE_TMP,
}
_CANARY_CLASSES: set[ContentClass] = {
    ContentClass.CANARY_AWS_CREDS, ContentClass.CANARY_ENV_FILE,
    ContentClass.CANARY_GIT_CONFIG, ContentClass.CANARY_SSH_KEY,
    ContentClass.CANARY_HONEYDOC, ContentClass.CANARY_HONEYDOC_DOCX,
    ContentClass.CANARY_HONEYDOC_PDF, ContentClass.CANARY_MYSQL_DUMP,
    ContentClass.CANARY_FINGERPRINT_HTML, ContentClass.CANARY_FINGERPRINT_SVG,
}


def current_payload() -> dict[str, Any]:
    """Export the live planner config as a JSON-safe dict.

    Wire shape returned by ``GET /api/v1/realism/config``."""
    return {
        "user_class_weights": _serialize_weights(_USER_CLASS_WEIGHTS),
        "system_class_weights": _serialize_weights(_SYSTEM_CLASS_WEIGHTS),
        "canary_class_weights": _serialize_weights(_CANARY_CLASS_WEIGHTS),
        "canary_probability": _CANARY_PROBABILITY,
    }


def apply_payload(payload: dict[str, Any]) -> list[str]:
    """Override the planner's live globals from a wire payload.

    Validates structurally and rebinds module-level names atomically
    per field — partial failures don't leave the planner in a torn
    state because validation happens before any rebind.

    Returns the list of ``content_class`` values that were dropped
    because they didn't belong on their target list (e.g. a canary
    class on the user list). Callers should surface this in the API
    response so operators know their entry didn't land.

    Unknown fields are ignored (forward-compat); fields not present
    leave the corresponding global untouched.
    """
    global _USER_CLASS_WEIGHTS, _SYSTEM_CLASS_WEIGHTS
    global _CANARY_CLASS_WEIGHTS, _CANARY_PROBABILITY

    new_user = _USER_CLASS_WEIGHTS
    new_system = _SYSTEM_CLASS_WEIGHTS
    new_canary = _CANARY_CLASS_WEIGHTS
    new_prob = _CANARY_PROBABILITY
    all_dropped: list[str] = []

    if "user_class_weights" in payload:
        new_user, dropped = _parse_weights(payload["user_class_weights"], _USER_CLASSES)
        all_dropped.extend(dropped)
    if "system_class_weights" in payload:
        new_system, dropped = _parse_weights(
            payload["system_class_weights"], _SYSTEM_CLASSES,
        )
        all_dropped.extend(dropped)
    if "canary_class_weights" in payload:
        new_canary, dropped = _parse_weights(
            payload["canary_class_weights"], _CANARY_CLASSES,
        )
        all_dropped.extend(dropped)
    if "canary_probability" in payload:
        prob = payload["canary_probability"]
        if not isinstance(prob, (int, float)) or not (0.0 <= prob <= 1.0):
            raise ValueError("canary_probability must be in [0.0, 1.0]")
        new_prob = float(prob)

    with _planner_lock:
        _USER_CLASS_WEIGHTS = new_user
        _SYSTEM_CLASS_WEIGHTS = new_system
        _CANARY_CLASS_WEIGHTS = new_canary
        _CANARY_PROBABILITY = new_prob

    return all_dropped


def reset_to_defaults() -> None:
    """Restore hardcoded defaults. Used by tests and the API reset path."""
    global _USER_CLASS_WEIGHTS, _SYSTEM_CLASS_WEIGHTS
    global _CANARY_CLASS_WEIGHTS, _CANARY_PROBABILITY
    with _planner_lock:
        _USER_CLASS_WEIGHTS = _DEFAULT_USER_CLASS_WEIGHTS
        _SYSTEM_CLASS_WEIGHTS = _DEFAULT_SYSTEM_CLASS_WEIGHTS
        _CANARY_CLASS_WEIGHTS = _DEFAULT_CANARY_CLASS_WEIGHTS
        _CANARY_PROBABILITY = _DEFAULT_CANARY_PROBABILITY


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

    # Canary first — they're rare (~3% of file picks), uniformly
    # weighted across generators.  Falling here means the orchestrator
    # plants a callback-bearing artifact this tick instead of an
    # inert one.
    if rng.random() < _CANARY_PROBABILITY:
        content_class = _weighted_pick(_CANARY_CLASS_WEIGHTS, rng)
        # Canary placement is the cultivator's job — plan.target_path
        # is advisory; a "" lets the cultivator override entirely.
        target_path = ""
        body_hint = None
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
                "kind=canary",
            ),
        )

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
