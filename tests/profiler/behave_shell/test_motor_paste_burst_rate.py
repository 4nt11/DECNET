"""Step 3: ``motor.paste_burst_rate`` — none / occasional / habitual."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def test_pure_typed_session_emits_none() -> None:
    events: list[AsciinemaEvent] = [(i * 0.1, "i", c) for i, c in enumerate("ls -la\r")]
    out = list(extract_session(events, sid="rate-typed"))
    assert _of(out, "motor.paste_burst_rate").value == "none"


def test_one_paste_in_ten_emits_occasional() -> None:
    # 1 paste + 9 single-char typed events → ratio 0.10 → occasional
    events: list[AsciinemaEvent] = [(0.0, "i", "echo paste\r")]
    events += [(0.5 + i * 0.1, "i", c) for i, c in enumerate("ls -la\rp")]
    out = list(extract_session(events, sid="rate-occasional"))
    assert _of(out, "motor.paste_burst_rate").value == "occasional"


def test_paste_majority_emits_habitual() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "echo a\r"),
        (1.0, "i", "echo b\r"),
        (2.0, "i", "echo c\r"),
        (3.0, "i", "x"),
    ]
    out = list(extract_session(events, sid="rate-habitual"))
    assert _of(out, "motor.paste_burst_rate").value == "habitual"


def test_zero_input_emits_nothing() -> None:
    out = list(extract_session([(0.0, "o", "hi\r\n")], sid="rate-empty"))
    assert [o for o in out if o.primitive == "motor.paste_burst_rate"] == []


def test_confidence_higher_for_habitual_than_occasional() -> None:
    pasted = [
        (0.0, "i", "echo a\r"), (1.0, "i", "echo b\r"), (2.0, "i", "echo c\r"),
    ]
    occasional = [(0.0, "i", "echo a\r")] + [
        (0.5 + i * 0.1, "i", c) for i, c in enumerate("ls -la\rps\r")
    ]
    h = _of(list(extract_session(pasted, sid="conf-h")), "motor.paste_burst_rate")
    o = _of(list(extract_session(occasional, sid="conf-o")), "motor.paste_burst_rate")
    assert h.confidence > o.confidence
