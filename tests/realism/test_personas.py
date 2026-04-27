"""Persona schema parsing + active-hours window tests."""
from __future__ import annotations

import json

from decnet.realism.personas import (
    EmailPersona,
    in_active_hours,
    login_for,
    parse_personas,
)


def _persona(**over) -> dict:
    base = {
        "name": "John Smith",
        "email": "john@corp.com",
        "role": "COO",
        "tone": "formal",
        "mannerisms": ["uses 'Best regards'"],
    }
    base.update(over)
    return base


def test_parse_empty_inputs():
    assert parse_personas(None) == []
    assert parse_personas("") == []
    assert parse_personas([]) == []


def test_parse_invalid_json_returns_empty_no_raise():
    assert parse_personas("{not json") == []


def test_parse_invalid_top_level_shape_returns_empty():
    assert parse_personas('{"not": "a list"}') == []


def test_parse_drops_invalid_entry_keeps_valid():
    raw = json.dumps([
        _persona(),
        {"name": "broken", "email": "not-an-email"},
        _persona(name="Sarah", email="sarah@corp.com"),
    ])
    parsed = parse_personas(raw)
    assert len(parsed) == 2
    assert {p.name for p in parsed} == {"John Smith", "Sarah"}


def test_parse_resolves_language_default_when_unset():
    raw = json.dumps([_persona()])
    parsed = parse_personas(raw, language_default="es")
    assert parsed[0].language == "es"


def test_parse_persona_language_overrides_default():
    raw = json.dumps([_persona(language="pt")])
    parsed = parse_personas(raw, language_default="es")
    assert parsed[0].language == "pt"


def test_parse_accepts_python_list_directly():
    parsed = parse_personas([_persona()])
    assert len(parsed) == 1


def test_uses_llms_heavily_default_false():
    parsed = parse_personas([_persona()])
    assert parsed[0].uses_llms_heavily is False


def test_uses_llms_heavily_can_be_set():
    parsed = parse_personas([_persona(uses_llms_heavily=True)])
    assert parsed[0].uses_llms_heavily is True


def test_active_hours_normal_window():
    p = EmailPersona(**_persona(active_hours="09:00-18:00"))
    assert in_active_hours(p, 12) is True
    assert in_active_hours(p, 8) is False
    assert in_active_hours(p, 18) is False
    assert in_active_hours(p, 9) is True


def test_active_hours_wraparound_window():
    p = EmailPersona(**_persona(active_hours="22:00-06:00"))
    assert in_active_hours(p, 23) is True
    assert in_active_hours(p, 0) is True
    assert in_active_hours(p, 5) is True
    assert in_active_hours(p, 7) is False


def test_active_hours_malformed_treats_as_always_on():
    p = EmailPersona(**_persona(active_hours="garbage"))
    assert in_active_hours(p, 0) is True
    assert in_active_hours(p, 23) is True


def test_active_hours_equal_window_treated_as_always_on():
    p = EmailPersona(**_persona(active_hours="10:00-10:00"))
    assert in_active_hours(p, 5) is True


def test_login_for_normalises_display_name():
    assert login_for("John Smith") == "johnsmith"
    assert login_for("alice") == "alice"


def test_login_for_falls_back_to_user_on_punctuation():
    # The realism namer and canary cultivator both rely on this so the
    # decky filesystem doesn't end up with an unexpected username.
    assert login_for("Mr. Robot") == "user"
    assert login_for("") == "user"
    assert login_for("Renée") == "user"  # non-ASCII falls back


def test_login_for_shared_by_naming_and_cultivator():
    """Single source of truth: realism naming and canary cultivator
    must agree on the persona→login mapping."""
    from decnet.canary import cultivator
    from decnet.realism import naming
    persona = "John Smith"
    expected = login_for(persona)
    assert naming._home(persona) == f"/home/{expected}"
    # cultivator imports login_for; not duplicated.
    assert cultivator.login_for is login_for
