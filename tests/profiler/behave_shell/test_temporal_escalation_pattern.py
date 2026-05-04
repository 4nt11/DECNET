"""Step E.2: ``temporal.escalation_pattern``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "temporal.escalation_pattern"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _commands_at(starts: list[float]) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    for s in starts:
        events.append((s, "i", "x\r"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "a"), (10.0, "i", "b")], sid="esc-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_uniform_pace_emits_sustained() -> None:
    """Even spacing across a long session → low CV → sustained."""
    starts = [i * 12.0 for i in range(15)]  # 15 cmds over 168s, 10 windows
    out = list(extract_session(_commands_at(starts), sid="esc-sus"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "sustained"


def test_silent_periods_with_spikes_emit_bursty() -> None:
    """Five tight bursts at session start, long silence, five at end."""
    starts = [0.0, 0.5, 1.0, 1.5, 2.0,                 # spike 1
              200.0, 200.5, 201.0, 201.5, 202.0]        # spike 2 after silence
    out = list(extract_session(_commands_at(starts), sid="esc-burst"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "bursty"


def test_variable_no_silence_emits_erratic() -> None:
    """Variable rate but every window populated → CV in (0.5, 1.0), zero_frac=0 → erratic."""
    # Last event at 120s so width = 12.0, n_windows = 10, bins [0,12), ..., [108,120).
    # Each window populated; counts skewed enough to push CV above 0.5 but
    # zero_frac stays at 0 so it can't qualify as bursty.
    starts = [
        0.0,                              # window 0 [0,12):       1
        13.0, 15.0,                       # window 1 [12,24):      2
        25.0,                             # window 2 [24,36):      1
        37.0, 38.0, 39.0, 40.0, 41.0,     # window 3 [36,48):      5
        50.0,                             # window 4 [48,60):      1
        62.0, 64.0,                       # window 5 [60,72):      2
        73.0,                             # window 6 [72,84):      1
        86.0, 87.0, 88.0, 89.0, 90.0,     # window 7 [84,96):      5
        100.0,                            # window 8 [96,108):     1
        115.0, 120.0,                     # window 9 [108,120]:    2
    ]
    out = list(extract_session(_commands_at(starts), sid="esc-err"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "erratic"


def test_short_session_low_confidence() -> None:
    """Below the sample-size floor — confidence drops."""
    short = list(extract_session(_commands_at([0.0, 1.0, 2.0]), sid="esc-short"))
    full = list(extract_session(_commands_at([i * 12.0 for i in range(15)]), sid="esc-full"))
    s = _of(short, PRIMITIVE)
    f = _of(full, PRIMITIVE)
    assert s.confidence < f.confidence
