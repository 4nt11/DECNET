"""Step 2: ``motor.input_modality`` — typed / pasted / mixed."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _by_primitive(observations: list, primitive: str):
    return [o for o in observations if o.primitive == primitive]


def test_pure_typed_session_emits_typed() -> None:
    events: list[AsciinemaEvent] = [(i * 0.1, "i", c) for i, c in enumerate("ls\r")]
    out = list(extract_session(events, sid="sess-typed"))
    obs = _by_primitive(out, "motor.input_modality")
    assert len(obs) == 1
    assert obs[0].value == "typed"
    assert obs[0].confidence == 0.75


def test_pure_pasted_session_emits_pasted() -> None:
    # Three large input events, no typing
    events: list[AsciinemaEvent] = [
        (0.0, "i", "echo first paste\r"),
        (1.0, "i", "echo second paste\r"),
        (2.0, "i", "echo third paste\r"),
    ]
    out = list(extract_session(events, sid="sess-pasted"))
    obs = _by_primitive(out, "motor.input_modality")
    assert len(obs) == 1
    assert obs[0].value == "pasted"


def test_mixed_session_emits_mixed() -> None:
    # 1 paste event + 9 single-char typed events → ratio 0.10 → in
    # between the typed (≤0.05) and pasted (≥0.40) thresholds → mixed
    events: list[AsciinemaEvent] = [(0.0, "i", "echo hello\r")]
    events += [(0.5 + i * 0.1, "i", c) for i, c in enumerate("ls -la\rps\r")]
    out = list(extract_session(events, sid="sess-mixed"))
    obs = _by_primitive(out, "motor.input_modality")
    assert len(obs) == 1
    assert obs[0].value == "mixed"


def test_zero_input_session_emits_nothing_for_modality() -> None:
    # Output-only session: no honest answer, so we don't emit.
    events: list[AsciinemaEvent] = [(0.0, "o", "welcome\r\n")]
    out = list(extract_session(events, sid="sess-empty-input"))
    assert _by_primitive(out, "motor.input_modality") == []


def test_observation_envelope_fields_are_populated() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "echo paste paste\r")]
    out = list(extract_session(
        events, sid="sess-env", evidence_ref="shard:/blob/sess-env",
    ))
    obs = _by_primitive(out, "motor.input_modality")[0]
    assert obs.source == "decnet/profiler/behave_shell/extract.py"
    assert obs.evidence_ref == "shard:/blob/sess-env"
    assert obs.window.start_ts == 0.0
    assert obs.window.end_ts == 0.0
    # envelope auto-populates id / ts / v
    assert obs.id and len(obs.id) > 0
    assert obs.v == 1
