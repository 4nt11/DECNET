"""Step B.1: ``motor.keystroke_cadence``."""
from __future__ import annotations

import random

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed_events(iats: list[float], terminator: bool = True) -> list[AsciinemaEvent]:
    """Build a typed input stream where consecutive single-char events are
    separated by ``iats``."""
    events: list[AsciinemaEvent] = []
    t = 0.0
    events.append((t, "i", "a"))
    for x in iats:
        t += x
        events.append((t, "i", "b"))
    if terminator:
        events.append((t + 0.1, "i", "\r"))
    return events


def test_too_few_inputs_no_emission() -> None:
    out = list(extract_session(_typed_events([0.1, 0.1]), sid="cad-low"))
    assert [o for o in out if o.primitive == "motor.keystroke_cadence"] == []


def test_huge_think_pauses_yield_no_typing_bursts() -> None:
    # Two events 5s apart → no IAT under IKI_THINK_MAX_S, and only 1
    # IAT total — below the 3-IAT-per-burst minimum. No burst, no emit.
    events: list[AsciinemaEvent] = [
        (0.0, "i", "a"),
        (5.0, "i", "b"),
        (10.0, "i", "c"),
        (15.0, "i", "d"),
        (20.0, "i", "e"),
    ]
    out = list(extract_session(events, sid="cad-no-bursts"))
    assert [o for o in out if o.primitive == "motor.keystroke_cadence"] == []


def test_uniform_iats_emit_steady() -> None:
    iats = [0.15] * 12
    out = list(extract_session(_typed_events(iats), sid="cad-steady"))
    obs = _of(out, "motor.keystroke_cadence")
    assert obs.value == "steady"
    assert obs.confidence == 0.70


def test_machine_iats_emit_machine() -> None:
    # Sub-5ms IATs with near-zero CV — no terminator IAT to inflate the
    # variance away from machine
    iats = [0.002] * 20
    out = list(extract_session(_typed_events(iats, terminator=False), sid="cad-machine"))
    obs = _of(out, "motor.keystroke_cadence")
    assert obs.value == "machine"
    assert obs.confidence == 0.85


def test_bursty_iats_emit_bursty() -> None:
    # Mean ~0.15 with moderate variance, CV between 0.5 and 1.5
    rng = random.Random(42)
    iats = []
    for _ in range(20):
        # Mostly fast, occasionally slow → CV in the bursty band
        iats.append(rng.choice([0.05, 0.05, 0.05, 0.30, 0.50]))
    out = list(extract_session(_typed_events(iats), sid="cad-bursty"))
    obs = _of(out, "motor.keystroke_cadence")
    assert obs.value == "bursty"


def test_hunt_and_peck_iats_emit_hunt_and_peck() -> None:
    # CV >= 1.5: extreme bimodal (very-fast + very-slow within burst).
    # Most IATs are tiny; a few are ~10x the mean — drives stdev/mean above 1.5.
    iats = [0.01] * 15 + [1.4] * 5
    out = list(extract_session(_typed_events(iats, terminator=False), sid="cad-hp"))
    obs = _of(out, "motor.keystroke_cadence")
    assert obs.value == "hunt_and_peck"
