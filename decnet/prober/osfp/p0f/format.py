"""p0f v2 ``.fp`` file parser.

Format (from the DSL spec at the top of every shipped ``.fp`` file):

    wwww:ttt:D:ss:OOO:QQ:OS:Details

Where:
  wwww   — window size:  literal int | '*' | '%nnn' | 'Snn' | 'Tnn'
  ttt    — initial TTL (literal int: 32/64/128/255 typically)
  D      — DF bit: '0' or '1'
  ss     — total IP packet length: literal int | '*' | '%nnn'
  OOO    — option order: comma/space-separated tokens, or '.' for none.
           Tokens: N, E, S, T, T0, P, Wnnn/W*/W%nnn, Mnnn/M*/M%nnn, ?n
  QQ     — quirks: concatenated single-letter flags, or '.' for none.
           Flags: P, Z, I, U, X, A, T, F, D, !, K, Q, 0, R
  OS     — genre, optionally prefixed '-' (userland), '@' (group),
           '*' (random/bogus), or combinations (e.g. '-@Windows').
  Details — free-text flavor/version.

Lines starting with '#' and blank lines are skipped.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from decnet.prober.osfp.p0f.signature import (
    IntSpec,
    OptionToken,
    Signature,
    WindowSpec,
    precompute_specificity,
)

logger = logging.getLogger("decnet.prober.osfp.p0f.format")

_OPTION_TOKEN_RE = re.compile(r"^([NESTPE]|T0|[MW\?])(\*|%\d+|\d+)?$")


class P0fParseError(ValueError):
    """Raised on genuinely malformed signature lines. The loader
    catches these and skips the offending line with a logger warning —
    one bad row doesn't disable the whole DB."""


def parse_p0f_v2(path: Path) -> list[Signature]:
    """Parse a p0f v2 ``.fp`` file and return a list of Signatures.

    Malformed lines are logged at WARNING and skipped rather than
    aborting the whole load — the vendored DB has ~375 entries and one
    corrupt row shouldn't prevent the other 374 from being usable.
    """
    out: list[Signature] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                sig = _parse_line(line)
            except P0fParseError as exc:
                logger.warning(
                    "p0f parse: skipping %s:%d — %s", path.name, lineno, exc,
                )
                continue
            out.append(sig)
    logger.debug("p0f parse: loaded %d signatures from %s", len(out), path.name)
    return out


def _parse_line(line: str) -> Signature:
    parts = line.split(":", 7)
    if len(parts) < 7:
        raise P0fParseError(f"expected 7+ colon-delimited fields, got {len(parts)}")
    if len(parts) == 7:
        parts = [*parts, ""]                     # empty details
    wss_s, ttl_s, df_s, tot_s, opts_s, quirks_s, os_s, details = parts

    wss = _parse_wss(wss_s)
    ttl = _parse_int_field(ttl_s, field="ttl")
    df = _parse_df(df_s)
    total_len = _parse_int_spec(tot_s)
    options = _parse_options(opts_s)
    quirks = _parse_quirks(quirks_s)
    os_name, is_userland, is_approx, is_random = _parse_os_genre(os_s)

    sig = Signature(
        wss=wss,
        ttl=ttl,
        df=df,
        total_len=total_len,
        options=options,
        quirks=quirks,
        os=os_name,
        flavor=details.strip(),
        notes="",
        is_userland=is_userland,
        is_approximate=is_approx,
        is_random=is_random,
    )
    # Replace specificity (frozen dataclass field default) with the
    # computed value via dataclasses.replace.
    from dataclasses import replace
    return replace(sig, specificity=precompute_specificity(sig))


def _parse_wss(s: str) -> WindowSpec:
    s = s.strip()
    if s == "*":
        return WindowSpec("any")
    if s.startswith("%"):
        try:
            return WindowSpec("mod", int(s[1:]))
        except ValueError as exc:
            raise P0fParseError(f"bad mod window {s!r}") from exc
    if s.startswith("S"):
        try:
            return WindowSpec("mss_mul", int(s[1:]))
        except ValueError as exc:
            raise P0fParseError(f"bad Snn window {s!r}") from exc
    if s.startswith("T"):
        try:
            return WindowSpec("mtu_mul", int(s[1:]))
        except ValueError as exc:
            raise P0fParseError(f"bad Tnn window {s!r}") from exc
    try:
        return WindowSpec("literal", int(s))
    except ValueError as exc:
        raise P0fParseError(f"bad literal window {s!r}") from exc


def _parse_int_field(s: str, *, field: str) -> int:
    """Parse a bare int field (used for TTL). No wildcards allowed."""
    try:
        return int(s.strip())
    except ValueError as exc:
        raise P0fParseError(f"bad {field}: {s!r}") from exc


def _parse_df(s: str) -> Optional[bool]:
    s = s.strip()
    if s == "*":
        return None
    if s == "0":
        return False
    if s == "1":
        return True
    raise P0fParseError(f"bad DF {s!r}; expected 0/1/*")


def _parse_int_spec(s: str) -> IntSpec:
    s = s.strip()
    if s == "*":
        return IntSpec("any")
    if s.startswith("%"):
        try:
            return IntSpec("mod", int(s[1:]))
        except ValueError as exc:
            raise P0fParseError(f"bad mod int {s!r}") from exc
    try:
        return IntSpec("literal", int(s))
    except ValueError as exc:
        raise P0fParseError(f"bad literal int {s!r}") from exc


def _parse_options(s: str) -> tuple[OptionToken, ...]:
    s = s.strip()
    if s in (".", ""):
        return (OptionToken("."),)
    normalized = s.replace(",", " ")
    tokens: list[OptionToken] = []
    for raw in normalized.split():
        tok = raw.strip()
        if not tok:
            continue
        tokens.append(_parse_option_token(tok))
    if not tokens:
        return (OptionToken("."),)
    return tuple(tokens)


def _parse_option_token(raw: str) -> OptionToken:
    # T0 — timestamp zero (not the TCP option '?0').
    if raw == "T0":
        return OptionToken("T0")
    m = _OPTION_TOKEN_RE.match(raw)
    if not m:
        raise P0fParseError(f"bad option token {raw!r}")
    kind, val_raw = m.group(1), m.group(2)
    if kind in ("N", "E", "S", "T", "P"):
        return OptionToken(kind)
    # M / W / ? expect a numeric predicate (or wildcard).
    if val_raw is None:
        raise P0fParseError(f"option {kind!r} missing required value")
    if val_raw == "*":
        spec = IntSpec("any")
    elif val_raw.startswith("%"):
        try:
            spec = IntSpec("mod", int(val_raw[1:]))
        except ValueError as exc:
            raise P0fParseError(f"bad {kind} mod value {val_raw!r}") from exc
    else:
        try:
            spec = IntSpec("literal", int(val_raw))
        except ValueError as exc:
            raise P0fParseError(f"bad {kind} literal value {val_raw!r}") from exc
    return OptionToken(kind, spec)


def _parse_quirks(s: str) -> frozenset[str]:
    s = s.strip()
    if s == "." or not s:
        return frozenset()
    # Quirks are a concatenated string of single-letter flags. '!' is a
    # valid quirk too.
    return frozenset(c for c in s if not c.isspace())


def _parse_os_genre(s: str) -> tuple[str, bool, bool, bool]:
    """Strip p0f's genre-prefix modifiers and return (os_name, is_userland, is_approx, is_random)."""
    is_userland = False
    is_approx = False
    is_random = False
    s = s.strip()
    # Prefixes can stack in any order — strip them all.
    changed = True
    while changed and s:
        changed = False
        if s.startswith("-"):
            is_userland = True
            s = s[1:]
            changed = True
        elif s.startswith("@"):
            is_approx = True
            s = s[1:]
            changed = True
        elif s.startswith("*"):
            is_random = True
            s = s[1:]
            changed = True
    return s, is_userland, is_approx, is_random
