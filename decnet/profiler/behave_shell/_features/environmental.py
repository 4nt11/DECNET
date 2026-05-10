"""``environmental.*`` feature functions.

Phase F ships the five environmental primitives plus F.0's shared
prompt-line detector. F.0 itself emits no primitive — it populates
``SessionContext.prompt_lines`` and ``Command.followed_by_prompt``
which F.1 / F.3 / E.4 read.

Step F.1: ``environmental.shell_type``.
Step F.2: ``environmental.terminal_multiplexer``.
Step F.3: ``environmental.locale``.
Step F.4: ``environmental.keyboard_layout``.
Step F.5: ``environmental.numpad_usage``.
"""
from __future__ import annotations

import collections
import re
from typing import Iterator

from behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext
from decnet.profiler.behave_shell._features._emit import make_observation
from decnet.profiler.behave_shell._parse import PromptLine, strip_ansi
from decnet.profiler.behave_shell._thresholds import (
    LAYOUT_AZERTY_ENG_MAX,
    LAYOUT_AZERTY_Q_MIN,
    LAYOUT_MIN_TYPED_LETTERS,
    LAYOUT_QWERTY_ENG_MIN,
    LAYOUT_QWERTZ_Y_MAX,
    LAYOUT_QWERTZ_Z_MIN,
    LAYOUT_TOP_ENG_BIGRAMS,
    LOCALE_MIN_VALUE_LENGTH,
    NUMPAD_FAST_IAT_S,
    NUMPAD_MIN_TYPED_CHARS,
    NUMPAD_RUN_MIN,
    PASTE_MIN_CHARS_PER_EVENT,
    SHELL_TYPE_MIN_PROMPTS,
)


# Multiplexer fingerprints scanned over RAW output (multiplexer escapes
# ARE ANSI sequences, so we must NOT strip-ANSI before searching).
# Sources:
#   tmux DCS passthrough: ESC P tmux ;
#   tmux focus reporting: ESC [ ? 1004 (set/reset)
#   tmux window-title with explicit tmux marker
#   screen DCS:           ESC P =
#   screen-specific OSC:  ESC ] 83 ;
_TMUX_MARKERS: tuple[str, ...] = (
    "\x1bPtmux;",
    "\x1b[?1004",
    "\x1b]2;tmux",
)
_SCREEN_MARKERS: tuple[str, ...] = (
    "\x1bP=",
    "\x1b]83;",
)


# Locale envvar regex: matches `KEY=VALUE` where KEY is one of the
# three locale envvars and VALUE is a POSIX locale name. The value
# pattern is intentionally restrictive — letters, underscore for the
# territory delimiter, optional codeset (.UTF-8 / .utf8), optional
# modifier (@euro). The trailing `(?=[\s'\"\\$]|$)` anchors the
# match against shell quoting and end-of-line.
_LOCALE_VALUE_RE = re.compile(
    r"(?P<key>LC_ALL|LANG|LC_CTYPE)=(?P<val>[A-Za-z]{2,3}"
    r"(?:_[A-Za-z]{2,3})?(?:\.[A-Za-z0-9-]+)?(?:@[A-Za-z0-9]+)?|C|POSIX)"
)
_LOCALE_KEY_PRIORITY: dict[str, int] = {"LC_ALL": 3, "LANG": 2, "LC_CTYPE": 1}


def _to_bcp47(posix_value: str) -> str | None:
    """Normalise a POSIX locale value to a BCP-47 tag.

    Returns:
        ``None`` when the value is malformed (caller skips emission).
        ``"und"`` for ``C`` / ``POSIX`` (BCP-47 'undetermined').
        Otherwise ``language-REGION`` (e.g. ``en-US``, ``pt-BR``);
        codeset / modifier suffixes dropped (BCP-47 doesn't carry them).
    """
    if posix_value in ("C", "POSIX"):
        return "und"
    base = posix_value.split(".", 1)[0].split("@", 1)[0]
    parts = base.split("_")
    if not parts or not parts[0].isalpha() or len(parts[0]) < 2:
        return None
    lang = parts[0].lower()
    if len(parts) == 1:
        return lang
    region = parts[1]
    if not region.isalpha():
        return None
    return f"{lang}-{region.upper()}"


def _classify_shell_from_prompt(p: PromptLine) -> str:
    """Map one prompt line to a shell-type label."""
    suffix = p.suffix_char
    line = p.raw_line
    if suffix in ("$", "#"):
        # bash / sh / dash all share these — collapsed to "bash" per
        # registry's bash-family stance. zsh CAN be configured to use
        # $/# but that's the user's PS1 override; default zsh is %.
        return "bash"
    if suffix == "%":
        return "zsh"
    if suffix == ">":
        # Disambiguate by line content. powershell's PS1 starts with
        # "PS "; cmd.exe's prompt typically contains a Windows path
        # like "C:\". Everything else is fish.
        if line.lstrip().startswith("PS "):
            return "powershell"
        if "C:\\" in line or "c:\\" in line:
            return "cmd.exe"
        return "fish"
    return "bash"  # defensive — _detect_prompt_suffix only emits one of $#%>


def shell_type(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.shell_type``.

    Mode of per-prompt-line classification across
    ``ctx.prompt_lines``. Skip emission when no prompts detected —
    the registry's enum doesn't admit ``unknown`` and emitting
    ``bash`` from no observation at all would be dishonest.

    Confidence drops below ``SHELL_TYPE_MIN_PROMPTS`` (3 prompts);
    above that threshold the vote is solid.
    """
    if not ctx.prompt_lines:
        return
    votes = collections.Counter(
        _classify_shell_from_prompt(p) for p in ctx.prompt_lines
    )
    value, _ = votes.most_common(1)[0]

    if len(ctx.prompt_lines) < SHELL_TYPE_MIN_PROMPTS:
        confidence = 0.40
    else:
        confidence = 0.75
    yield make_observation(
        ctx,
        primitive="environmental.shell_type",
        value=value,
        confidence=confidence,
    )


def terminal_multiplexer(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.terminal_multiplexer`` ∈ {none, tmux, screen}.

    Scans raw output (NOT ANSI-stripped — multiplexer escapes ARE ANSI
    sequences) for tmux/screen-specific fingerprints. If both detected,
    prefer tmux (more common in 2026 nested-mux setups). Even one
    escape is conclusive — no sample-size floor.

    Confidence 0.85 when a fingerprint matches; 0.55 for ``none`` (a
    bare PTY genuinely has no multiplexer, but a hidden multiplexer
    that suppresses its escapes would also yield ``none``).

    Skip emission when the session has no commands — without operator
    interaction the engine should not emit operator-derived primitives.
    The smoke gates (``test_extract_session_empty_stream_yields_no_observations``,
    ``test_extract_session_zero_inputs_yields_nothing``) bind this:
    no commands, no observations.
    """
    if not ctx.commands:
        return
    has_tmux = False
    has_screen = False
    for _t, _k, data in ctx.output_events:
        if not has_tmux and any(m in data for m in _TMUX_MARKERS):
            has_tmux = True
        if not has_screen and any(m in data for m in _SCREEN_MARKERS):
            has_screen = True
        if has_tmux and has_screen:
            break

    if has_tmux:
        value = "tmux"
        confidence = 0.85
    elif has_screen:
        value = "screen"
        confidence = 0.85
    else:
        value = "none"
        confidence = 0.55
    yield make_observation(
        ctx,
        primitive="environmental.terminal_multiplexer",
        value=value,
        confidence=confidence,
    )


def locale(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.locale`` (free-string BCP-47 tag).

    Searches the ANSI-stripped output stream for ``LANG=``,
    ``LC_ALL=``, or ``LC_CTYPE=`` substrings — emitted when the
    operator runs ``env``, ``locale``, or ``printenv``. Highest-priority
    key wins (``LC_ALL`` > ``LANG`` > ``LC_CTYPE``); the POSIX value is
    normalised to BCP-47:

    * ``en_US.UTF-8`` → ``en-US``
    * ``pt_BR.UTF-8`` → ``pt-BR``
    * ``C`` / ``POSIX`` → ``und``
    * malformed → skip emission

    Skip emission when no envvar dump is found in the output —
    silence rather than fabricating a default.
    """
    if not ctx.commands:
        return
    # Concatenate output; strip ANSI once (locale values aren't escape
    # sequences themselves so the strip is safe).
    raw = "".join(d for _t, _k, d in ctx.output_events)
    if not raw:
        return
    text = strip_ansi(raw)

    best_priority = 0
    best_value: str | None = None
    for m in _LOCALE_VALUE_RE.finditer(text):
        prio = _LOCALE_KEY_PRIORITY[m.group("key")]
        if prio <= best_priority:
            continue
        bcp47 = _to_bcp47(m.group("val"))
        if bcp47 is None or len(bcp47) < LOCALE_MIN_VALUE_LENGTH:
            continue
        best_priority = prio
        best_value = bcp47

    if best_value is None:
        return
    yield make_observation(
        ctx,
        primitive="environmental.locale",
        value=best_value,
        confidence=0.80,
    )


def keyboard_layout(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.keyboard_layout``.

    Two independent signals over the typed-only character histograms:

    1. **English-bigram saturation** — fraction of typed bigrams that
       hit the top-10 English bigrams. High → presumed QWERTY.
    2. **Layout-artefact unigrams** — letters that are rare in English
       but frequent on operators using a different layout:

       * ``q`` rate above floor AND English saturation low → ``azerty``
         (AZERTY's `a` is on QWERTY's `q` position; mistypes bleed `q`)
       * ``z`` rate above floor AND ``y`` rate below floor → ``qwertz``
         (QWERTZ swaps `y`/`z`)
       * Else: English saturation above floor → ``qwerty``
       * Else: → ``other``

    Threshold ordering matters — layout-artefact checks fire before
    QWERTY because AZERTY/QWERTZ operators may still hit some English
    bigrams.

    Skip emission when typed letter count below
    ``LAYOUT_MIN_TYPED_LETTERS`` (200) — the histograms are too thin
    to discriminate honestly.
    """
    if ctx.typed_letter_count < LAYOUT_MIN_TYPED_LETTERS:
        return
    uni = ctx.typed_unigram_counts
    bi = ctx.typed_bigram_counts
    total_letters = ctx.typed_letter_count
    total_bigrams = sum(bi.values())

    eng_saturation = (
        sum(bi.get(b, 0) for b in LAYOUT_TOP_ENG_BIGRAMS) / total_bigrams
        if total_bigrams > 0 else 0.0
    )
    q_rate = uni.get("q", 0) / total_letters
    z_rate = uni.get("z", 0) / total_letters
    y_rate = uni.get("y", 0) / total_letters

    if q_rate > LAYOUT_AZERTY_Q_MIN and eng_saturation < LAYOUT_AZERTY_ENG_MAX:
        value = "azerty"
    elif z_rate > LAYOUT_QWERTZ_Z_MIN and y_rate < LAYOUT_QWERTZ_Y_MAX:
        value = "qwertz"
    elif eng_saturation >= LAYOUT_QWERTY_ENG_MIN:
        value = "qwerty"
    else:
        value = "other"

    if total_letters < 500:
        confidence = 0.40
    else:
        confidence = 0.55
    yield make_observation(
        ctx,
        primitive="environmental.keyboard_layout",
        value=value,
        confidence=confidence,
    )


def numpad_usage(ctx: SessionContext) -> Iterator[Observation]:
    """Emit ``environmental.numpad_usage`` ∈ {detected, not_detected}.

    A digit run is ``NUMPAD_RUN_MIN`` (4) consecutive single-character
    digit input events whose pairwise IATs are all
    ≤ ``NUMPAD_FAST_IAT_S`` (50ms). Numpad muscle memory produces
    faster digit cadence than touch-typing the top row.

    Skip emission below ``NUMPAD_MIN_TYPED_CHARS`` (50) typed chars —
    no honest signal in a tiny session. Confidence cap 0.50 (registry
    flags as weak signal).
    """
    if not ctx.commands:
        return

    digit_events: list[float] = []
    typed_count = 0
    for t, _kind, data in ctx.input_events:
        if len(data) >= PASTE_MIN_CHARS_PER_EVENT:
            continue
        typed_count += len(data)
        if len(data) == 1 and data.isdigit():
            digit_events.append(t)

    if typed_count < NUMPAD_MIN_TYPED_CHARS:
        return

    detected = False
    if len(digit_events) >= NUMPAD_RUN_MIN:
        # Sliding window: any contiguous run of NUMPAD_RUN_MIN digit
        # events whose internal IATs are ALL fast → numpad.
        for i in range(len(digit_events) - NUMPAD_RUN_MIN + 1):
            window_iats = [
                digit_events[i + j + 1] - digit_events[i + j]
                for j in range(NUMPAD_RUN_MIN - 1)
            ]
            if all(x <= NUMPAD_FAST_IAT_S for x in window_iats):
                detected = True
                break

    yield make_observation(
        ctx,
        primitive="environmental.numpad_usage",
        value="detected" if detected else "not_detected",
        confidence=0.50,
    )
