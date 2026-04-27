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


def test_pick_never_returns_canary_class_in_stage3() -> None:
    deckies = [_decky()]
    for seed in range(40):
        plan = pick(deckies, _NOW, rand=random.Random(seed))
        if plan is None:
            continue
        assert not plan.content_class.is_canary(), (
            "canary class slipped into the realism planner; cultivator "
            "lands in stage 7"
        )


def test_pick_persists_persona_window_in_notes() -> None:
    plan = pick([_decky()], _NOW, rand=random.Random(0))
    assert plan is not None
    # The plan's notes carry the persona name and the window — useful
    # for the dashboard's "why this file" inspector.
    assert any("persona=admin" in n for n in plan.notes)
    assert any("window=" in n for n in plan.notes)
