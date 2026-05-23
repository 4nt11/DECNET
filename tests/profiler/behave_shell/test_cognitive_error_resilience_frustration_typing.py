# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step D.6: ``cognitive.error_resilience.frustration_typing``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "cognitive.error_resilience.frustration_typing"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float, dt: float) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _build(blocks: list[tuple[str, bool, float]]) -> list[AsciinemaEvent]:
    """Synthesise a session.

    ``blocks`` is a list of (token, errored, dt) tuples. Each command
    gets its own time slot 2s apart; ``dt`` is the within-command IAT.
    """
    events: list[AsciinemaEvent] = []
    for i, (tok, errored, dt) in enumerate(blocks):
        t0 = i * 2.0
        events.extend(_typed(f"{tok}\r", t0=t0, dt=dt))
        if errored:
            cmd_end = t0 + len(tok) * dt
            events.append((cmd_end + 0.10, "o", f"bash: {tok}: command not found\n"))
        else:
            cmd_end = t0 + len(tok) * dt
            events.append((cmd_end + 0.10, "o", "ok\n"))
    return events


def test_no_errors_no_emission() -> None:
    out = list(extract_session(_build([("ls", False, 0.05)] * 5), sid="ft-clean"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_no_baseline_no_emission() -> None:
    """Every command errored — no clean baseline → skip emission."""
    out = list(extract_session(_build([("foo", True, 0.05)] * 5), sid="ft-allerr"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_matching_speeds_emit_low() -> None:
    """Same dt for post-error and post-success commands → delta ≈ 0 → low."""
    blocks = [
        ("ok", False, 0.05),
        ("ok", False, 0.05),
        ("foo", True, 0.05),
        ("ok", False, 0.05),  # post-err: dt=0.05
        ("ok", False, 0.05),  # post-ok:  dt=0.05
        ("foo", True, 0.05),
        ("ok", False, 0.05),  # post-err: dt=0.05
        ("ok", False, 0.05),
    ]
    out = list(extract_session(_build(blocks), sid="ft-low"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "low"


def test_huge_speed_change_emits_high() -> None:
    """Post-error commands typed 4x slower than post-success → delta=3 → high."""
    blocks = [
        ("ok", False, 0.05),
        ("ok", False, 0.05),  # post-ok: dt=0.05
        ("foo", True, 0.05),
        ("ok", False, 0.20),  # post-err: dt=0.20 (4x slower)
        ("ok", False, 0.05),  # post-ok: dt=0.05
        ("foo", True, 0.05),
        ("ok", False, 0.20),
        ("ok", False, 0.05),
    ]
    out = list(extract_session(_build(blocks), sid="ft-high"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "high"


def test_low_post_error_count_reduces_confidence() -> None:
    short = [
        ("ok", False, 0.05),
        ("foo", True, 0.05),
        ("ok", False, 0.05),
        ("ok", False, 0.05),
    ]
    full_blocks = [("ok", False, 0.05)]
    for _ in range(6):
        full_blocks.append(("foo", True, 0.05))
        full_blocks.append(("ok", False, 0.05))
    s = _of(list(extract_session(_build(short), sid="ft-short")), PRIMITIVE)
    f = _of(list(extract_session(_build(full_blocks), sid="ft-full")), PRIMITIVE)
    assert s.confidence < f.confidence
