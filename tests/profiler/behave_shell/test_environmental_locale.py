"""Step F.3: ``environmental.locale``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._features.environmental import _to_bcp47
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "environmental.locale"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


# ── _to_bcp47 ──────────────────────────────────────────────────────────────


def test_to_bcp47_lang_region() -> None:
    assert _to_bcp47("en_US.UTF-8") == "en-US"
    assert _to_bcp47("pt_BR.UTF-8") == "pt-BR"
    assert _to_bcp47("de_DE@euro") == "de-DE"


def test_to_bcp47_language_only() -> None:
    assert _to_bcp47("fr") == "fr"


def test_to_bcp47_c_posix() -> None:
    assert _to_bcp47("C") == "und"
    assert _to_bcp47("POSIX") == "und"


def test_to_bcp47_malformed() -> None:
    assert _to_bcp47("X") is None        # too short
    assert _to_bcp47("en_99") is None    # non-alpha region


# ── feature integration ────────────────────────────────────────────────────


def test_no_envvar_dump_no_emission() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "file1\nfile2\n"),
    ]
    out = list(extract_session(events, sid="loc-none"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_lang_envvar_dump_emits_bcp47() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("env\r"),
        (0.20, "o", "PATH=/usr/bin\nLANG=en_US.UTF-8\nUSER=anti\n"),
    ]
    obs = _of(list(extract_session(events, sid="loc-en")), PRIMITIVE)
    assert obs.value == "en-US"


def test_lc_all_takes_precedence_over_lang() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("env\r"),
        (0.20, "o", "LANG=en_US.UTF-8\nLC_ALL=pt_BR.UTF-8\nUSER=anti\n"),
    ]
    obs = _of(list(extract_session(events, sid="loc-prec")), PRIMITIVE)
    assert obs.value == "pt-BR"


def test_c_locale_emits_und() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("env\r"),
        (0.20, "o", "LANG=C\nUSER=anti\n"),
    ]
    obs = _of(list(extract_session(events, sid="loc-und")), PRIMITIVE)
    assert obs.value == "und"


def test_pii_locale_value_only_no_surrounding_output() -> None:
    """Surrounding output isn't leaked — only the parsed BCP-47 value."""
    events: list[AsciinemaEvent] = [
        *_typed("env\r"),
        (0.20, "o", "SECRET_TOKEN=abcdef123\nLANG=en_US.UTF-8\n"),
    ]
    out = list(extract_session(events, sid="loc-pii"))
    obs = _of(out, PRIMITIVE)
    serialised = obs.model_dump_json()
    assert "SECRET_TOKEN" not in serialised
    assert "abcdef123" not in serialised
    assert "en-US" in serialised
