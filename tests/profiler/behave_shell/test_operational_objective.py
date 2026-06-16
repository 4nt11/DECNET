# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.1: ``operational.objective`` ∈ {recon, exfil, persistence,
lateral, destructive}."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "operational.objective"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _cmd(token: str, t0: float, *, with_prompt: bool = True) -> list[AsciinemaEvent]:
    events = _typed(f"{token}\r", t0=t0)
    cmd_end = t0 + len(token) * 0.05
    if with_prompt:
        events.append((cmd_end + 0.10, "o", "out\nanti@host:~$ "))
    else:
        events.append((cmd_end + 0.10, "o", "out\n"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="g1-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_too_few_classified_skipped() -> None:
    """Two recon commands < INTENT_MIN_COMMANDS=3 → no emission."""
    events = _cmd("ls", t0=0.0) + _cmd("pwd", t0=1.0)
    out = list(extract_session(events, sid="g1-thin"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_unclassified_commands_skipped() -> None:
    """``vim`` / ``foo`` / ``bar`` aren't in any intent set."""
    events = (
        _cmd("vim", t0=0.0)
        + _cmd("foo", t0=1.0)
        + _cmd("bar", t0=2.0)
        + _cmd("baz", t0=3.0)
    )
    out = list(extract_session(events, sid="g1-unkn"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_majority_recon_emits_recon() -> None:
    events = (
        _cmd("ls", t0=0.0)
        + _cmd("pwd", t0=1.0)
        + _cmd("whoami", t0=2.0)
    )
    obs = _of(list(extract_session(events, sid="g1-recon")), PRIMITIVE)
    assert obs.value == "recon"
    assert 0.39 < obs.confidence <= 0.60


def test_majority_destructive_outranks_recon() -> None:
    """Mixed: 3 destructive + 2 recon → destructive."""
    events = (
        _cmd("rm", t0=0.0)
        + _cmd("ls", t0=1.0)
        + _cmd("dd", t0=2.0)
        + _cmd("pwd", t0=3.0)
        + _cmd("shred", t0=4.0)
    )
    obs = _of(list(extract_session(events, sid="g1-dest")), PRIMITIVE)
    assert obs.value == "destructive"


def test_high_count_raises_confidence() -> None:
    events: list[AsciinemaEvent] = []
    for i, tok in enumerate(["ls", "pwd", "whoami", "id", "uname", "ps", "find"]):
        events += _cmd(tok, t0=float(i))
    obs = _of(list(extract_session(events, sid="g1-conf")), PRIMITIVE)
    assert obs.value == "recon"
    assert obs.confidence == 0.60


def test_persistence_classifies() -> None:
    events = (
        _cmd("crontab", t0=0.0)
        + _cmd("systemctl", t0=1.0)
        + _cmd("passwd", t0=2.0)
    )
    obs = _of(list(extract_session(events, sid="g1-persist")), PRIMITIVE)
    assert obs.value == "persistence"


def test_exfil_classifies() -> None:
    events = (
        _cmd("curl", t0=0.0)
        + _cmd("wget", t0=1.0)
        + _cmd("scp", t0=2.0)
    )
    obs = _of(list(extract_session(events, sid="g1-exfil")), PRIMITIVE)
    assert obs.value == "exfil"


def test_lateral_classifies() -> None:
    events = (
        _cmd("ssh", t0=0.0)
        + _cmd("kubectl", t0=1.0)
        + _cmd("docker", t0=2.0)
    )
    obs = _of(list(extract_session(events, sid="g1-lat")), PRIMITIVE)
    assert obs.value == "lateral"
