"""Step 6: ``cognitive.command_branch_diversity``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _commands(first_tokens: list[str]) -> list[AsciinemaEvent]:
    """One command per token, well-spaced."""
    events: list[AsciinemaEvent] = []
    t = 0.0
    for tok in first_tokens:
        events.append((t, "i", f"{tok} arg\r"))
        t += 1.0
    return events


def test_under_floor_emits_unknown_high_confidence() -> None:
    out = list(extract_session(_commands(["ls", "ps", "id"]), sid="bd-low"))
    obs = _of(out, "cognitive.command_branch_diversity")
    assert obs.value == "unknown"
    assert obs.confidence == 1.0


def test_unique_first_tokens_emit_linear_playbook() -> None:
    # 8 distinct tools — ratio 1.0 → linear_playbook
    tokens = ["uname", "id", "whoami", "pwd", "ls", "ps", "netstat", "ss"]
    out = list(extract_session(_commands(tokens), sid="bd-linear"))
    obs = _of(out, "cognitive.command_branch_diversity")
    assert obs.value == "linear_playbook"
    assert obs.confidence == 0.80


def test_repeated_first_tokens_emit_adaptive_branching() -> None:
    # 8 commands, only 3 distinct — ratio 0.375 < 0.60
    tokens = ["curl", "curl", "curl", "ls", "curl", "ls", "curl", "ps"]
    out = list(extract_session(_commands(tokens), sid="bd-adaptive"))
    obs = _of(out, "cognitive.command_branch_diversity")
    assert obs.value == "adaptive_branching"


def test_middle_band_biases_to_adaptive() -> None:
    # 7 commands, 5 unique → ratio ≈ 0.71 — between 0.60 and 0.80.
    # The doc instructs us to bias to adaptive in the ambiguous middle.
    tokens = ["a", "b", "c", "d", "e", "a", "b"]
    out = list(extract_session(_commands(tokens), sid="bd-mid"))
    obs = _of(out, "cognitive.command_branch_diversity")
    assert obs.value == "adaptive_branching"


def test_pii_no_command_bodies_in_observation() -> None:
    out = list(extract_session(_commands(
        ["secret_arg_payload"] * 6,
    ), sid="bd-pii"))
    obs = _of(out, "cognitive.command_branch_diversity")
    # Whatever the verdict, the raw token must not be in the dump
    serialised = obs.model_dump_json()
    assert "secret_arg_payload" not in serialised
