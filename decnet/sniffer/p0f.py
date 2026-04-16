"""
Passive OS fingerprinting (p0f-lite) for the DECNET sniffer.

Pure-Python lookup module. Given the values of an incoming TCP SYN packet
(TTL, window, MSS, window-scale, and TCP option ordering), returns a coarse
OS bucket (linux / windows / macos_ios / freebsd / openbsd / nmap / unknown)
plus derived hop distance and inferred initial TTL.

Rationale
---------
Full p0f v3 distinguishes several dozen OS/tool profiles by combining dozens
of low-level quirks (OLEN, WSIZE, EOL padding, PCLASS, quirks, payload class).
For DECNET we only need a coarse bucket — enough to tag an attacker as
"linux beacon" vs "windows interactive" vs "active scan". The curated
table below covers default stacks that dominate real-world attacker traffic.

References (public p0f v3 DB, nmap-os-db, and Mozilla OS Fingerprint table):
    https://github.com/p0f/p0f/blob/master/p0f.fp

No external dependencies.
"""

from __future__ import annotations

from decnet.telemetry import traced as _traced

# ─── TTL → initial TTL bucket ───────────────────────────────────────────────

# Common "hop 0" TTLs. Packets decrement TTL once per hop, so we round up
# the observed TTL to the nearest known starting value.
_TTL_BUCKETS: tuple[int, ...] = (32, 64, 128, 255)


def initial_ttl(ttl: int) -> int:
    """
    Round *ttl* up to the nearest known initial-TTL bucket.

    A SYN with TTL=59 was almost certainly emitted by a Linux/BSD host
    (initial 64) five hops away; TTL=120 by a Windows host (initial 128)
    eight hops away.
    """
    for bucket in _TTL_BUCKETS:
        if ttl <= bucket:
            return bucket
    return 255


def hop_distance(ttl: int) -> int:
    """
    Estimate hops between the attacker and the sniffer based on TTL.

    Upper-bounded at 64 (anything further has most likely been mangled
    by a misconfigured firewall or a TTL-spoofing NAT).
    """
    dist = initial_ttl(ttl) - ttl
    if dist < 0:
        return 0
    if dist > 64:
        return 64
    return dist


# ─── OS signature table (TTL bucket, window, MSS, wscale, option-order) ─────

# Each entry is a set of loose predicates. If all predicates match, the
# OS label is returned. First-match wins. `None` means "don't care".
#
# The option signatures use the short-code alphabet from
# decnet/prober/tcpfp.py :: _OPT_CODES (M=MSS, N=NOP, W=WScale,
# T=Timestamp, S=SAckOK, E=EOL).

_SIGNATURES: tuple[tuple[dict, str], ...] = (
    # ── nmap -sS / -sT default probe  ───────────────────────────────────────
    # nmap crafts very distinctive SYNs: tiny window (1024/4096/etc.), full
    # option set including WScale=10 and SAckOK. Match these first so they
    # don't get misclassified as Linux.
    (
        {
            "ttl_bucket": 64,
            "window_in": {1024, 2048, 3072, 4096, 31337, 32768, 65535},
            "mss": 1460,
            "wscale": 10,
            "options": "M,W,T,S,S",
        },
        "nmap",
    ),
    (
        {
            "ttl_bucket": 64,
            "window_in": {1024, 2048, 3072, 4096, 31337, 32768, 65535},
            "options_starts_with": "M,W,T,S",
        },
        "nmap",
    ),
    # ── macOS / iOS default SYN  (match before Linux — shares TTL 64)  ──────
    # TTL 64, window 65535, MSS 1460, WScale 6, specific option order
    # M,N,W,N,N,T,S,E (Darwin signature with EOL padding).
    (
        {
            "ttl_bucket": 64,
            "window": 65535,
            "wscale": 6,
            "options": "M,N,W,N,N,T,S,E",
        },
        "macos_ios",
    ),
    (
        {
            "ttl_bucket": 64,
            "window_in": {65535},
            "wscale_in": {5, 6},
            "has_timestamps": True,
            "options_ends_with": "E",
        },
        "macos_ios",
    ),
    # ── FreeBSD default SYN  (TTL 64, no EOL)  ───────────────────────────────
    (
        {
            "ttl_bucket": 64,
            "window": 65535,
            "wscale": 6,
            "has_sack": True,
            "has_timestamps": True,
            "options_no_eol": True,
        },
        "freebsd",
    ),
    # ── Linux (kernel 3.x – 6.x) default SYN  ───────────────────────────────
    # TTL 64, window 29200 / 64240 / 65535, MSS 1460, WScale 7, full options.
    (
        {
            "ttl_bucket": 64,
            "window_min": 5000,
            "wscale_in": {6, 7, 8, 9, 10, 11, 12, 13, 14},
            "has_sack": True,
            "has_timestamps": True,
        },
        "linux",
    ),
    # ── OpenBSD default SYN  ─────────────────────────────────────────────────
    # TTL 64, window 16384, WScale 3-6, MSS 1460
    (
        {
            "ttl_bucket": 64,
            "window_in": {16384, 16960},
            "wscale_in": {3, 4, 5, 6},
        },
        "openbsd",
    ),
    # ── Windows 10/11/Server default SYN  ────────────────────────────────────
    # TTL 128, window 64240/65535, MSS 1460, WScale 8, SACK+TS
    (
        {
            "ttl_bucket": 128,
            "window_min": 8192,
            "wscale_in": {2, 6, 7, 8},
            "has_sack": True,
        },
        "windows",
    ),
    # ── Windows 7/XP (legacy)  ───────────────────────────────────────────────
    (
        {
            "ttl_bucket": 128,
            "window_in": {8192, 16384, 65535},
        },
        "windows",
    ),
    # ── Embedded / Cisco / network gear  ─────────────────────────────────────
    (
        {
            "ttl_bucket": 255,
        },
        "embedded",
    ),
)


def _match_signature(
    sig: dict,
    ttl: int,
    window: int,
    mss: int,
    wscale: int | None,
    options_sig: str,
) -> bool:
    """Evaluate every predicate in *sig* against the observed values."""
    tb = initial_ttl(ttl)
    if "ttl_bucket" in sig and sig["ttl_bucket"] != tb:
        return False
    if "window" in sig and sig["window"] != window:
        return False
    if "window_in" in sig and window not in sig["window_in"]:
        return False
    if "window_min" in sig and window < sig["window_min"]:
        return False
    if "mss" in sig and sig["mss"] != mss:
        return False
    if "wscale" in sig and sig["wscale"] != wscale:
        return False
    if "wscale_in" in sig and wscale not in sig["wscale_in"]:
        return False
    if "has_sack" in sig:
        if sig["has_sack"] != ("S" in options_sig):
            return False
    if "has_timestamps" in sig:
        if sig["has_timestamps"] != ("T" in options_sig):
            return False
    if "options" in sig and sig["options"] != options_sig:
        return False
    if "options_starts_with" in sig and not options_sig.startswith(sig["options_starts_with"]):
        return False
    if "options_ends_with" in sig and not options_sig.endswith(sig["options_ends_with"]):
        return False
    if "options_no_eol" in sig and sig["options_no_eol"] and "E" in options_sig:
        return False
    return True


@_traced("sniffer.p0f_guess_os")
def guess_os(
    ttl: int,
    window: int,
    mss: int = 0,
    wscale: int | None = None,
    options_sig: str = "",
) -> str:
    """
    Return a coarse OS bucket for the given SYN characteristics.

    One of: "linux", "windows", "macos_ios", "freebsd", "openbsd",
    "embedded", "nmap", "unknown".
    """
    for sig, label in _SIGNATURES:
        if _match_signature(sig, ttl, window, mss, wscale, options_sig):
            return label
    return "unknown"
