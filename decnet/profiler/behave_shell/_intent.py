"""Phase G — shared command-intent + lexical-counter vocabulary.

Used by:
* ``operational.objective``        (G.1)  via ``INTENT_SETS``
* ``operational.opsec_discipline`` (G.2)  via ``OPSEC_HISTORY_TOKENS``
* ``emotional_valence.valence``    (G.5)  via ``POSITIVE_LEXEMES`` / ``NEGATIVE_LEXEMES``
* ``emotional_valence.frustration_venting`` (G.8) via ``OBSCENITY_LEXEMES``

All ``*_TOKENS`` frozensets contain ``hash_token()`` SHA256 hexes — the
only PII-safe handle on a command's first token. Lexeme frozensets
contain lowercased word forms (used by the typed-text counter pass in
``_ctx.py`` to *count* matches without retaining text).

Set membership is intentionally overlapping. ``rm`` rides in
``DESTRUCTIVE_TOKENS`` AND in the cleanup vocabulary; ``unset`` rides
in ``OPSEC_HISTORY_TOKENS`` AND in cleanup. G.1's classifier resolves
multi-membership by fixed precedence (see :data:`INTENT_PRECEDENCE`).
"""
from __future__ import annotations

from decnet.profiler.behave_shell._parse import hash_token

# ── operational.objective intent sets (G.1) ────────────────────────────────
RECON_TOKENS: frozenset[str] = frozenset(
    hash_token(t) for t in (
        "ls", "pwd", "whoami", "id", "uname", "ps", "netstat", "ss",
        "cat", "find", "which", "env", "printenv", "hostname", "w",
        "who", "date", "uptime", "df", "du", "free", "lsof", "lsblk",
    )
)
EXFIL_TOKENS: frozenset[str] = frozenset(
    hash_token(t) for t in (
        "curl", "wget", "scp", "rsync", "nc", "ncat", "socat", "tar",
        "base64", "xxd", "python", "python3", "openssl",
    )
)
PERSISTENCE_TOKENS: frozenset[str] = frozenset(
    hash_token(t) for t in (
        "crontab", "systemctl", "useradd", "usermod", "passwd", "chsh",
        "at", "service", "chkconfig", "update-rc.d", "authorized_keys",
    )
)
LATERAL_TOKENS: frozenset[str] = frozenset(
    hash_token(t) for t in (
        "ssh", "telnet", "rsh", "rlogin", "ftp", "sftp", "mosh",
        "kubectl", "docker", "psql", "mysql", "redis-cli",
    )
)
DESTRUCTIVE_TOKENS: frozenset[str] = frozenset(
    hash_token(t) for t in (
        "rm", "dd", "mkfs", "shred", "wipe", "kill", "pkill", "killall",
        "truncate", "fdisk",
    )
)

# G.1 majority-vote classifier walks first_token_hash → category in this
# order; first hit wins. ``destructive`` outranks ``persistence`` because
# a session that destroys outweighs one that also installs cron jobs;
# ``exfil`` outranks ``lateral`` because pulling data is the more
# specific signal.
INTENT_PRECEDENCE: tuple[tuple[str, frozenset[str]], ...] = (
    ("destructive",  DESTRUCTIVE_TOKENS),
    ("persistence",  PERSISTENCE_TOKENS),
    ("exfil",        EXFIL_TOKENS),
    ("lateral",      LATERAL_TOKENS),
    ("recon",        RECON_TOKENS),
)


def classify_intent(first_token_hash: str) -> str | None:
    """Return the registry intent label for ``first_token_hash``.

    ``None`` if the hash isn't in any intent set.
    """
    for label, hashes in INTENT_PRECEDENCE:
        if first_token_hash in hashes:
            return label
    return None


# ── operational.opsec_discipline (G.2) ─────────────────────────────────────
# History-clearing / log-tampering vocabulary (first-token).
OPSEC_HISTORY_TOKENS: frozenset[str] = frozenset(
    hash_token(t) for t in (
        "history", "unset", "export", "set", "script",
    )
)


# ── emotional_valence lexicons (G.5 / G.8) ────────────────────────────────
# Lowercased lexeme word-forms. Membership-tested against typed-text
# tokens during the single-pass histogram walk in ``_ctx.py``. No raw
# text retained — only per-set integer counters.
#
# Stop-word collisions with registry values (``no``, ``none``, ``ok``,
# ``hell``→``shell_type``) are excluded — registry value strings travel
# through observations and would trigger PII regression checks. Kept
# lexemes are those that don't collide with primitive value vocabulary.
POSITIVE_LEXEMES: frozenset[str] = frozenset({
    "thanks", "nice", "cool", "great", "okay",
    "perfect", "love", "awesome",
})
NEGATIVE_LEXEMES: frozenset[str] = frozenset({
    "wtf", "damn", "crap", "ugh", "broken", "stupid",
    "hate", "stuck", "wrong",
})
OBSCENITY_LEXEMES: frozenset[str] = frozenset({
    "fuck", "fucking", "fucked", "shit", "bitch", "ass", "cunt",
    "dick", "asshole",
})

ALL_LEXEMES: frozenset[str] = (
    POSITIVE_LEXEMES | NEGATIVE_LEXEMES | OBSCENITY_LEXEMES
)
LEXEME_MAX_LEN: int = max((len(x) for x in ALL_LEXEMES), default=0)
