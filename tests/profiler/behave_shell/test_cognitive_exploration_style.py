"""Step D.2: ``cognitive.exploration_style``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _cmds(tokens: list[str]) -> list[AsciinemaEvent]:
    """One command per token, evenly spaced one second apart."""
    events: list[AsciinemaEvent] = []
    for i, tok in enumerate(tokens):
        t0 = i * 1.0
        for j, c in enumerate(tok):
            events.append((t0 + j * 0.05, "i", c))
        events.append((t0 + len(tok) * 0.05, "i", "\r"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="es-empty"))
    assert [o for o in out if o.primitive == "cognitive.exploration_style"] == []


def test_all_unique_tools_emits_methodical() -> None:
    """Linear progression through new tools: low R, low J → methodical."""
    out = list(extract_session(
        _cmds(["ls", "ps", "id", "uname", "whoami", "pwd", "env", "date"]),
        sid="es-meth",
    ))
    obs = _of(out, "cognitive.exploration_style")
    assert obs.value == "methodical"


def test_drilling_one_tool_emits_targeted() -> None:
    """Same tool repeated → high R, low J → targeted."""
    out = list(extract_session(
        _cmds(["curl", "curl", "curl", "curl", "curl", "curl", "curl", "curl"]),
        sid="es-tgt",
    ))
    obs = _of(out, "cognitive.exploration_style")
    assert obs.value == "targeted"


def test_jumping_among_old_tools_emits_chaotic() -> None:
    """Backtracking among prior tools → high J → chaotic."""
    out = list(extract_session(
        _cmds(["a", "b", "c", "a", "c", "b", "a", "b"]),
        sid="es-chaos",
    ))
    obs = _of(out, "cognitive.exploration_style")
    assert obs.value == "chaotic"


def test_low_sample_count_reduces_confidence() -> None:
    short = list(extract_session(_cmds(["a", "b", "c"]), sid="es-short"))
    full = list(extract_session(_cmds(["a", "b", "c", "d", "e", "f"]), sid="es-full"))
    s = _of(short, "cognitive.exploration_style")
    f = _of(full, "cognitive.exploration_style")
    assert s.confidence < f.confidence


def test_pii_no_command_bodies_in_observation() -> None:
    out = list(extract_session(
        _cmds(["secret_payload"] * 6),
        sid="es-pii",
    ))
    obs = _of(out, "cognitive.exploration_style")
    assert "secret_payload" not in obs.model_dump_json()
