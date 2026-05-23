# SPDX-License-Identifier: AGPL-3.0-or-later
"""p0f v2 signature + observation matching/scoring.

A :class:`Signature` is one parsed row from a ``.fp`` file. A match
against an observation dict (the kind ``sniffer_rollup`` hands us)
returns a confidence score in [0, 1], with higher scores indicating
more-specific matches. Wildcards and modulo predicates match but
contribute less to the confidence than an exact literal match, so
when multiple signatures fire against one observation we can pick the
most-specific one.

Observation dict shape (all keys optional — a provider returns None
if too few match-relevant fields are present):

    {
        "window":      int | None,     # TCP window size
        "mss":         int | None,     # TCP MSS option value
        "wscale":      int | None,     # TCP window-scale option value
        "ttl":         int | None,     # initial-TTL bucket (32/64/128/255)
        "df":          bool | None,    # IP Don't-Fragment flag
        "total_len":   int | None,     # IP total length (SYN)
        "options_sig": str  | None,    # e.g. "M,N,W,T" or "M1460,N,W7,S"
        "quirks":      frozenset[str] | None,  # e.g. {"Z", "P"}
    }

The scoring is our extension — upstream p0f is "first match wins"
using the order of entries in ``.fp``. We score so the factory can
compare across multiple DB files (p0f.fp + p0fa.fp) and return the
winner objectively.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ─── Field predicates ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class WindowSpec:
    """Parsed 'wss' field. Encodes p0f v2's window-size predicate DSL:

    - 'literal'  →  observed window == value
    - 'mss_mul'  →  observed window == MSS * value   (p0f "Snn")
    - 'mtu_mul'  →  observed window == (MSS+40) * value   (p0f "Tnn")
    - 'mod'      →  observed window % value == 0   (p0f "%nnn")
    - 'any'      →  wildcard    (p0f "*")
    """

    kind: str
    value: Optional[int] = None

    def matches(self, window: Optional[int], mss: Optional[int]) -> bool:
        if self.kind == "any":
            return True
        if window is None:
            return False
        if self.kind == "literal":
            return window == self.value
        if self.kind == "mod":
            return self.value is not None and self.value > 0 and (window % self.value == 0)
        if self.kind == "mss_mul":
            return mss is not None and self.value is not None and window == mss * self.value
        if self.kind == "mtu_mul":
            return mss is not None and self.value is not None and window == (mss + 40) * self.value
        return False


@dataclass(frozen=True)
class IntSpec:
    """Wildcard-or-modulo int predicate, used for MSS / wscale / total_len."""

    kind: str             # 'literal' | 'mod' | 'any'
    value: Optional[int] = None

    def matches(self, observed: Optional[int]) -> bool:
        if self.kind == "any":
            return True
        if observed is None:
            return False
        if self.kind == "literal":
            return observed == self.value
        if self.kind == "mod":
            return self.value is not None and self.value > 0 and (observed % self.value == 0)
        return False


@dataclass(frozen=True)
class OptionToken:
    """One TCP option as it appears in a signature's options list.

    - kind='N'  EOL 'E'  SACK-permitted 'S'  timestamp 'T'  zero-timestamp 'T0'
    - kind='M'  MSS option, value = IntSpec
    - kind='W'  window-scale option, value = IntSpec
    - kind='?'  unknown option number, value = IntSpec (literal = option number)
    - kind='.'  no-options sentinel (singleton — matches only empty option list)
    """

    kind: str
    value: Optional[IntSpec] = None

    def matches_literal(self, token: "OptionToken") -> bool:
        """True when *this* signature token matches an observed *token*.

        Signature-side carries the wildcard/modulo predicate; observed
        side is always a literal (or kind-only for flag options).
        """
        if self.kind != token.kind:
            return False
        if self.value is None:
            return True
        if token.value is None:
            return False
        # Both have IntSpecs — match via predicate.
        return self.value.matches(token.value.value)


# ─── Signature ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Signature:
    """One parsed row from a p0f v2 .fp file.

    ``label_prefix`` captures p0f's os-genre modifiers:
      - ``-``  userland stack (not a real OS; flagged scanner/browser)
      - ``@``  approximate / group match
      - ``*``  random or bogus userland
    These prefixes are stripped from ``os``; the flags survive here
    for the profiler to decide e.g. "do I promote nmap to tool_guesses?"
    """

    wss: WindowSpec
    ttl: int
    df: Optional[bool]
    total_len: IntSpec
    options: tuple[OptionToken, ...]   # in order; use (OptionToken('.'),) for none
    quirks: frozenset[str]
    os: str
    flavor: str
    notes: str
    is_userland: bool = False    # '-' prefix
    is_approximate: bool = False  # '@' prefix
    is_random: bool = False       # '*' prefix (distinct from wildcard)

    # Cache: a crude "specificity budget" precomputed at parse time.
    # Higher = more constrained fields, used as a tie-breaker when two
    # signatures match the same observation.
    specificity: float = field(default=0.0)

    def score(self, obs: dict[str, Any]) -> Optional[float]:
        """Return a confidence in [0, 1] on match, or None if any field
        rejects the observation.

        Soft-field semantics: ``df`` and ``total_len`` are treated as
        "skip check when observation is missing" — the sniffer doesn't
        currently emit either, and a literal-constraint sig shouldn't
        reject a match solely because the observation is upstream-
        incomplete. Hard fields (``window``, ``ttl``, ``options_sig``,
        ``quirks``) still hard-reject on absent or mismatched input —
        those are the real discriminators."""
        mss = obs.get("mss")
        # Window (hard)
        if not self.wss.matches(obs.get("window"), mss):
            return None
        # TTL — initial-TTL bucket must match exactly. The profiler is
        # expected to have rounded the observed TTL up to the nearest
        # bucket already via decnet.sniffer.p0f.initial_ttl. (hard)
        obs_ttl = obs.get("ttl")
        if obs_ttl is None or obs_ttl != self.ttl:
            return None
        # DF (soft — skip when unknown)
        if self.df is not None:
            obs_df = obs.get("df")
            if obs_df is not None and bool(obs_df) != self.df:
                return None
        # Total length (soft — skip when unknown)
        obs_total = obs.get("total_len")
        if obs_total is not None and not self.total_len.matches(obs_total):
            return None
        # Options (hard)
        if not _options_match(self.options, obs.get("options_sig")):
            return None
        # Quirks — must match as a set. (hard)
        obs_quirks = obs.get("quirks") or frozenset()
        if not isinstance(obs_quirks, frozenset):
            obs_quirks = frozenset(obs_quirks)
        if self.quirks != obs_quirks:
            return None
        # All fields matched — return the precomputed specificity.
        return self.specificity


def _options_match(sig_opts: tuple[OptionToken, ...], obs_sig: Optional[str]) -> bool:
    """Match signature option sequence against observation's comma/space-
    separated option string."""
    obs_tokens = _parse_observation_options(obs_sig)
    # Special case: signature is '.' (no-options sentinel).
    if len(sig_opts) == 1 and sig_opts[0].kind == ".":
        return len(obs_tokens) == 0
    if len(sig_opts) != len(obs_tokens):
        return False
    return all(s.matches_literal(o) for s, o in zip(sig_opts, obs_tokens))


_OBS_TOKEN_RE = re.compile(r"^([A-Z\?])(\d+)?$")


def _parse_observation_options(opts_sig: Optional[str]) -> list[OptionToken]:
    """Convert the observation-side options string (from
    tcp_syn_fingerprint / tcpfp_fingerprint SD fields) into a list of
    literal OptionTokens. Accepts comma or space delimiters and tokens
    like 'M1460', 'W7', 'T', 'T0', 'N', 'E', '?47'.
    """
    if not opts_sig:
        return []
    normalized = opts_sig.replace(",", " ")
    out: list[OptionToken] = []
    for raw in normalized.split():
        token = raw.strip()
        if not token:
            continue
        if token == "T0":  # nosec B105 — TCP option name ("Timestamp zero"), not a credential
            out.append(OptionToken("T0"))
            continue
        m = _OBS_TOKEN_RE.match(token)
        if not m:
            # Unknown token — represent as opaque "?" with no value so
            # nothing matches it. Better than raising.
            out.append(OptionToken("?", IntSpec("literal", -1)))
            continue
        kind, num = m.group(1), m.group(2)
        if num is None:
            out.append(OptionToken(kind))
        else:
            out.append(OptionToken(kind, IntSpec("literal", int(num))))
    return out


def precompute_specificity(sig: Signature) -> float:
    """Crude specificity score used when comparing matching signatures.

    Each field contributes a weight; wildcards and modulo predicates
    contribute less. Tuned so a fully-literal signature scores ~1.0 and
    a near-wildcard signature scores ~0.1.
    """
    w = 0.0
    total = 0.0
    # Window (weight 3 — very discriminating)
    total += 3
    if sig.wss.kind == "literal":
        w += 3.0
    elif sig.wss.kind in ("mss_mul", "mtu_mul"):
        w += 2.5
    elif sig.wss.kind == "mod":
        w += 1.5
    # TTL — always literal, contributes a flat 1
    total += 1
    w += 1.0
    # DF (weight 1)
    total += 1
    if sig.df is not None:
        w += 1.0
    # Total length (weight 1)
    total += 1
    if sig.total_len.kind == "literal":
        w += 1.0
    elif sig.total_len.kind == "mod":
        w += 0.5
    # Options (weight 3 — highly discriminating when literal)
    total += 3
    if not (len(sig.options) == 1 and sig.options[0].kind == "."):
        literal_opts = sum(
            1 for o in sig.options
            if o.value is None or o.value.kind == "literal"
        )
        if sig.options:
            w += 3.0 * (literal_opts / len(sig.options))
    else:
        # "no options" is itself a signal.
        w += 2.0
    # Quirks (weight 1 — most sigs have no quirks so this is a small edge)
    total += 1
    if sig.quirks:
        w += 1.0
    return round(w / total, 4)
