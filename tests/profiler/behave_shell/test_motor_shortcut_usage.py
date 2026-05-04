"""Step C.2: ``motor.shell_mastery.shortcut_usage``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import AsciinemaEvent

PRIMITIVE = "motor.shell_mastery.shortcut_usage"

# Three of the seven readline shortcuts; using distinct codes ensures
# we are counting bytes, not just one specific char.
CTRL_A = "\x01"
CTRL_E = "\x05"
CTRL_R = "\x12"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _command(t0: float, body: str) -> list[AsciinemaEvent]:
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
    out = list(extract_session([(0.0, "i", "ls")], sid="sc-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_zero_shortcuts_emit_none() -> None:
    out = list(extract_session(_session(["ls", "pwd", "id", "uname", "whoami"]),
                               sid="sc-none"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "none"
    assert obs.confidence == 0.65


def test_moderate_rate_emits_moderate() -> None:
    # 2 ctrl bytes across 10 commands = 0.20/cmd → moderate; not near
    # either of the 0.05 / 0.30 boundaries (>10%).
    bodies = [f"ls{CTRL_A}"] * 2 + ["pwd"] * 8
    out = list(extract_session(_session(bodies), sid="sc-moderate"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "moderate"
    assert obs.confidence == 0.65


def test_heavy_rate_emits_heavy() -> None:
    # 10 ctrl bytes across 5 commands = 2.0/cmd → heavy.
    bodies = [f"ls{CTRL_A}{CTRL_E}", f"vi{CTRL_R}f", f"cd{CTRL_A}"] + [
        f"cat{CTRL_R}", f"ps{CTRL_E}"
    ]
    out = list(extract_session(_session(bodies), sid="sc-heavy"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "heavy"


def test_sub_threshold_rate_rounds_to_none() -> None:
    # 1 ctrl byte across 50 commands = 0.02/cmd, below MODERATE_MIN.
    bodies = [f"ls{CTRL_A}"] + ["pwd"] * 49
    out = list(extract_session(_session(bodies, gap=0.5), sid="sc-rounddown"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "none"


def test_near_boundary_drops_confidence() -> None:
    # 3 ctrl bytes across 10 commands = 0.30/cmd — exactly the heavy
    # boundary. Confidence drops.
    bodies = [f"ls{CTRL_A}{CTRL_E}{CTRL_R}"] + ["pwd"] * 9
    out = list(extract_session(_session(bodies), sid="sc-boundary"))
    obs = _of(out, PRIMITIVE)
    assert obs.confidence == 0.55


def test_few_commands_drops_confidence() -> None:
    out = list(extract_session(_session(["ls", "pwd", "id", "exit"]),
                               sid="sc-low-n"))
    obs = _of(out, PRIMITIVE)
    assert obs.confidence == 0.40


def test_segmentation_populates_shortcut_count() -> None:
    """Multiple distinct ctrl bytes inside one command count once each;
    counters reset on the command boundary."""
    events = _command(0.0, f"ls{CTRL_A}{CTRL_E}{CTRL_R}") + _command(5.0, "pwd")
    ctx = build_session_context(events, sid="seg-sc", source="t")
    assert len(ctx.commands) == 2
    assert ctx.commands[0].shortcut_count == 3
    assert ctx.commands[1].shortcut_count == 0


def test_non_shortcut_ctrl_bytes_not_counted() -> None:
    """Only the seven pinned ctrl bytes count. ^C (0x03) / ^L (0x0c)
    must not bump shortcut_count."""
    events = _command(0.0, "ls\x03\x0c")
    ctx = build_session_context(events, sid="seg-sc-other", source="t")
    assert ctx.commands[0].shortcut_count == 0
