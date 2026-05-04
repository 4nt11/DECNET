"""Step E.3: ``temporal.lifecycle_markers.landing_ritual``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "temporal.lifecycle_markers.landing_ritual"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _cmds(tokens: list[str]) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    for i, tok in enumerate(tokens):
        t0 = i * 1.0
        for j, c in enumerate(tok):
            events.append((t0 + j * 0.05, "i", c))
        events.append((t0 + len(tok) * 0.05, "i", "\r"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "a")], sid="lr-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_recon_survey_emits_present() -> None:
    """First commands are uname/id/whoami → present."""
    out = list(extract_session(
        _cmds(["uname", "id", "whoami", "ls", "ps", "cat"]),
        sid="lr-present",
    ))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "present"


def test_single_recon_token_below_threshold_emits_absent() -> None:
    """One recon token in first-5 isn't enough (need ≥2) → absent."""
    out = list(extract_session(
        _cmds(["uname", "vim", "edit", "save", "exit", "ls"]),
        sid="lr-onehit",
    ))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "absent"


def test_no_recon_tokens_emits_absent() -> None:
    out = list(extract_session(
        _cmds(["vim", "edit", "save", "make", "ls", "cat"]),
        sid="lr-absent",
    ))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "absent"


def test_recon_after_first_n_does_not_count() -> None:
    """Only the first N=5 commands are considered."""
    out = list(extract_session(
        _cmds(["vim", "edit", "save", "make", "test", "uname", "id", "whoami"]),
        sid="lr-late",
    ))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "absent"


def test_short_session_low_confidence() -> None:
    short = list(extract_session(_cmds(["uname", "id"]), sid="lr-short"))
    full = list(extract_session(_cmds(["uname", "id", "whoami", "ls", "ps"]), sid="lr-full"))
    s = _of(short, PRIMITIVE)
    f = _of(full, PRIMITIVE)
    assert s.confidence < f.confidence
