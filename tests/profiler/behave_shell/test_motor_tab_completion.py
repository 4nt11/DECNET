"""Step C.1: ``motor.shell_mastery.tab_completion``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import AsciinemaEvent

PRIMITIVE = "motor.shell_mastery.tab_completion"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _command(t0: float, body: str) -> list[AsciinemaEvent]:
    """One command at ``t0``: every byte of ``body`` then a ``\\r``.

    Bytes arrive 50ms apart so the segmentation logic sees event-level
    timestamps that fall inside the synthesised command window.
    """
    events: list[AsciinemaEvent] = []
    t = t0
    for c in body:
        events.append((t, "i", c))
        t += 0.05
    events.append((t, "i", "\r"))
    return events


def _session(bodies: list[str], gap: float = 1.0) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    t = 0.0
    for body in bodies:
        events.extend(_command(t, body))
        t = events[-1][0] + gap
    return events


def test_no_commands_no_emission() -> None:
    """No \\r/\\n → no commands → no honest ratio to report."""
    out = list(extract_session([(0.0, "i", "ls")], sid="tab-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_zero_tabs_emit_none() -> None:
    out = list(extract_session(_session(["ls", "pwd", "id", "uname", "whoami", "date"]),
                               sid="tab-none"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "none"
    assert obs.confidence == 0.75


def test_majority_tabs_emit_habitual() -> None:
    # 5 of 6 commands carry a \t → ratio ≈ 0.83, well above 0.50.
    bodies = ["ls\t", "cd\t/tmp", "ec\thello", "cat\tf", "vi\t", "exit"]
    out = list(extract_session(_session(bodies), sid="tab-habitual"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "habitual"
    assert obs.confidence == 0.75


def test_low_tab_rate_emits_occasional() -> None:
    # 2 of 10 → ratio 0.20 (below 0.30, above 0); not near a boundary.
    bodies = ["ls\t"] * 2 + ["pwd"] * 8
    out = list(extract_session(_session(bodies), sid="tab-occasional"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "occasional"
    assert obs.confidence == 0.75


def test_gap_band_rounds_down_to_occasional() -> None:
    # 4 of 10 → ratio 0.40, sits in the registry's 30%-50% gap which
    # we round DOWN to occasional. Not near either boundary at >10%.
    bodies = ["ls\t"] * 4 + ["pwd"] * 6
    out = list(extract_session(_session(bodies), sid="tab-gap"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "occasional"


def test_near_boundary_drops_confidence() -> None:
    # 3 of 10 → 0.30 — exactly the occasional boundary. Confidence drops.
    bodies = ["ls\t"] * 3 + ["pwd"] * 7
    out = list(extract_session(_session(bodies), sid="tab-boundary"))
    obs = _of(out, PRIMITIVE)
    assert obs.confidence == 0.55


def test_few_commands_drops_confidence() -> None:
    # 4 commands < SHELL_MASTERY_MIN_COMMANDS=5 → confidence floor 0.40.
    out = list(extract_session(_session(["ls", "pwd", "id", "exit"]),
                               sid="tab-low-n"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "none"
    assert obs.confidence == 0.40


def test_segmentation_populates_tab_count() -> None:
    """End-to-end: tabs inside a command increment ``Command.tab_count``
    once per byte and don't leak into the next command."""
    events = _command(0.0, "l\ts\t") + _command(5.0, "pwd")
    ctx = build_session_context(events, sid="seg-tab", source="t")
    assert len(ctx.commands) == 2
    assert ctx.commands[0].tab_count == 2
    assert ctx.commands[1].tab_count == 0
