"""Realism planner — picks (decky, persona, class, action, mtime).

Stage 3 ships create-only plans; the edit branch lands in 3b.  Tests
pin the diurnal gate, the eligibility filter, and the create
contract.
"""
from __future__ import annotations

import random
from datetime import datetime, timezone

import pytest

from decnet.realism.personas import EmailPersona
from decnet.realism.planner import pick
from decnet.realism.taxonomy import ContentClass


def _persona(name: str = "admin", window: str = "00:00-00:00") -> EmailPersona:
    return EmailPersona(
        name=name,
        email=f"{name}@corp.com",
        role="ops",
        tone="direct",
        active_hours=window,
    )


def _decky(uuid: str = "u1", name: str = "decky-01", personas=None) -> dict:
    return {
        "uuid": uuid,
        "name": name,
        "_realism_personas": personas or [_persona()],
    }


_NOW = datetime(2026, 4, 27, 14, 0, tzinfo=timezone.utc)


def test_pick_returns_none_when_no_deckies() -> None:
    assert pick([], _NOW) is None


def test_pick_returns_none_when_decky_has_no_personas() -> None:
    assert pick([{"uuid": "u1", "name": "d", "_realism_personas": []}], _NOW) is None


def test_pick_filters_personas_outside_window() -> None:
    # A persona pegged to 01:00-02:00 with now=14:00 must not be picked.
    out_of_hours = _persona(window="01:00-02:00")
    deckies = [_decky(personas=[out_of_hours])]
    assert pick(deckies, _NOW) is None


def test_pick_returns_create_plan_with_mtime_in_past() -> None:
    deckies = [_decky()]
    plan = pick(deckies, _NOW, rand=random.Random(0))
    assert plan is not None
    assert plan.action == "create"
    assert plan.decky_uuid == "u1"
    assert plan.persona == "admin"
    assert plan.target_path.startswith("/")
    assert plan.body_hint
    assert plan.mtime < _NOW


def test_pick_distributes_across_user_and_system_classes() -> None:
    deckies = [_decky()]
    seen: set[ContentClass] = set()
    for seed in range(80):
        plan = pick(deckies, _NOW, rand=random.Random(seed))
        if plan is not None:
            seen.add(plan.content_class)
    # Across 80 seeds we should hit both buckets — at least one user
    # class and at least one system class — otherwise the weights or
    # the 70/30 split is broken.
    user_classes = {c for c in seen if c.is_user_class()}
    system_classes = {c for c in seen if c.is_system_class()}
    assert user_classes, f"no user-class plans in 80 trials: {seen}"
    assert system_classes, f"no system-class plans in 80 trials: {seen}"


def test_canary_picks_are_rare() -> None:
    """Stage 7: canary content_classes ARE picked, but bounded.

    The documented rate is ~3% of file picks per
    decnet/realism/planner.py:_CANARY_PROBABILITY.  We trial a large
    sample and assert the rate stays under a generous ceiling so a
    typo bumping the constant to 30% explodes here loudly.
    """
    deckies = [_decky()]
    canary_count = 0
    create_count = 0
    for seed in range(500):
        plan = pick(deckies, _NOW, rand=random.Random(seed))
        if plan is None:
            continue
        create_count += 1
        if plan.content_class.is_canary():
            canary_count += 1
    # 3% target with a 6% upper bound — sampling noise on 500 trials
    # is comfortably below this for the documented rate.
    rate = canary_count / max(1, create_count)
    assert rate <= 0.06, f"canary rate {rate:.2%} exceeds 6% ceiling"
    assert canary_count > 0, "expected at least one canary across 500 seeds"


def test_pick_persists_persona_window_in_notes() -> None:
    plan = pick([_decky()], _NOW, rand=random.Random(0))
    assert plan is not None
    # The plan's notes carry the persona name and the window — useful
    # for the dashboard's "why this file" inspector.
    assert any("persona=admin" in n for n in plan.notes)
    assert any("window=" in n for n in plan.notes)
