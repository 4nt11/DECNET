"""Step F.1: ``environmental.shell_type``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "environmental.shell_type"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _session(prompt_lines: list[str]) -> list[AsciinemaEvent]:
    """Build a synthetic session: one ``ls`` per prompt, prompt printed
    as the post-execution output of that command."""
    events: list[AsciinemaEvent] = []
    for i, prompt in enumerate(prompt_lines):
        events.extend(_typed("ls\r", t0=i * 1.0))
        events.append((i * 1.0 + 0.5, "o", f"out\n{prompt}"))
    return events


def test_no_prompts_no_emission() -> None:
    events = _typed("ls\r", t0=0.0) + [(0.5, "o", "file1\n")]
    out = list(extract_session(events, sid="sht-noprompt"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_bash_prompt_emits_bash() -> None:
    out = list(extract_session(_session(["anti@host:~$ "] * 5), sid="sht-bash"))
    assert _of(out, PRIMITIVE).value == "bash"


def test_root_prompt_still_bash() -> None:
    """# is bash root, not a separate shell."""
    out = list(extract_session(_session(["root@host:/etc# "] * 5), sid="sht-root"))
    assert _of(out, PRIMITIVE).value == "bash"


def test_zsh_prompt_emits_zsh() -> None:
    out = list(extract_session(_session(["host% "] * 5), sid="sht-zsh"))
    assert _of(out, PRIMITIVE).value == "zsh"


def test_fish_prompt_emits_fish() -> None:
    out = list(extract_session(_session(["anti@host ~> "] * 5), sid="sht-fish"))
    assert _of(out, PRIMITIVE).value == "fish"


def test_powershell_prompt_emits_powershell() -> None:
    out = list(extract_session(
        _session(["PS C:\\Users\\anti> "] * 5), sid="sht-ps",
    ))
    assert _of(out, PRIMITIVE).value == "powershell"


def test_cmd_exe_prompt_emits_cmd_exe() -> None:
    out = list(extract_session(_session(["C:\\Users\\anti>"] * 5), sid="sht-cmd"))
    assert _of(out, PRIMITIVE).value == "cmd.exe"


def test_majority_wins() -> None:
    """Mixed prompts, bash majority → bash."""
    out = list(extract_session(_session([
        "anti@host:~$ ",
        "anti@host:~$ ",
        "anti@host:~$ ",
        "host% ",  # one zsh outlier
        "anti@host:~$ ",
    ]), sid="sht-mix"))
    assert _of(out, PRIMITIVE).value == "bash"


def test_few_prompts_low_confidence() -> None:
    short = list(extract_session(_session(["anti@host:~$ "] * 2), sid="sht-short"))
    full = list(extract_session(_session(["anti@host:~$ "] * 6), sid="sht-full"))
    s = _of(short, PRIMITIVE)
    f = _of(full, PRIMITIVE)
    assert s.confidence < f.confidence
