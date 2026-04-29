"""Per-content-class filename generators.

The pre-realism orchestrator emitted ``notes-1777315854.txt``
(unix-epoch suffix) — a tell on first glance.  Real users name
``notes.txt``, ``TODO.md``, ``backup-2025-04.sql.gz``.  Real systems
write ``cron.log``, ``cron.log.1``, ``cron.log.2.gz`` (logrotate
shape, no epoch).

Stage 3 ships **deterministic templates only**, persona-conditioned.
Stage 6 wires LLM enrichment for the user-classes (``note``, ``todo``,
``draft``, ``script``); the deterministic templates remain the
fallback when LLM is disabled or times out.

The factory mirrors :func:`decnet.canary.factory.get_generator`:
caller passes a :class:`~decnet.realism.taxonomy.ContentClass`; we
return the namer registered for it.  Renaming a content_class is a
schema change and would invalidate ``synthetic_files.path`` lookups,
so the dispatch is exhaustive — no silent fallbacks for unknown
classes.
"""
from __future__ import annotations

import secrets
import string
from typing import Callable, Optional

from decnet.realism.personas import login_for
from decnet.realism.taxonomy import ContentClass


# Persona → home-dir convention.  Most personas are linux-style; the
# rare "windows" persona gets ``C:\\Users\\<persona>\\Documents`` style
# paths (out of scope until per-OS personas land).  For now everything
# is POSIX.
def _home(persona: str) -> str:
    """Return the canonical home directory for *persona*."""
    return f"/home/{login_for(persona)}"


def _random_token(rng: secrets.SystemRandom, length: int = 6) -> str:
    """Lowercase-alphanum token of length *length* — like ``mkstemp``."""
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(length))


# ── User-class namers ──────────────────────────────────────────────────────


_NOTE_NAMES: tuple[str, ...] = (
    "notes.txt", "scratch.md", "ideas.txt", "Untitled-3.txt",
    "draft.md", "keys.txt", "passwords.txt", "TODO.md",
)

_TODO_NAMES: tuple[str, ...] = (
    "TODO.md", "todo.txt", "things.md", "tasks.txt", "punchlist.md",
)

_DRAFT_NAMES: tuple[str, ...] = (
    "Q3-budget-DRAFT.md", "proposal.md", "letter.txt",
    "rfc-internal.md", "memo.txt", "1on1-notes.md",
)

_SCRIPT_NAMES: tuple[str, ...] = (
    "backup.sh", "deploy.sh", "cleanup.sh", "rotate.sh",
    "fix.py", "tmp.py", "scratch.py",
)


def _name_user(
    persona: str, names: tuple[str, ...], rng: secrets.SystemRandom,
) -> str:
    return f"{_home(persona)}/{rng.choice(names)}"


def _name_note(persona: str, rng: secrets.SystemRandom) -> str:
    return _name_user(persona, _NOTE_NAMES, rng)


def _name_todo(persona: str, rng: secrets.SystemRandom) -> str:
    return _name_user(persona, _TODO_NAMES, rng)


def _name_draft(persona: str, rng: secrets.SystemRandom) -> str:
    return _name_user(persona, _DRAFT_NAMES, rng)


def _name_script(persona: str, rng: secrets.SystemRandom) -> str:
    return _name_user(persona, _SCRIPT_NAMES, rng)


# ── System-class namers ────────────────────────────────────────────────────


# logrotate skeleton: cron.log, cron.log.1, cron.log.2.gz.  No epoch
# suffix — the realism failure today is `cron-1777317867.log`.
_CRON_LOGROTATE: tuple[str, ...] = (
    "/var/log/cron.log", "/var/log/cron.log.1", "/var/log/cron.log.2.gz",
)
_DAEMON_LOGROTATE: tuple[str, ...] = (
    "/var/log/daemon.log", "/var/log/syslog", "/var/log/messages",
    "/var/log/auth.log", "/var/log/auth.log.1",
)


def _name_log_cron(persona: str, rng: secrets.SystemRandom) -> str:
    return rng.choice(_CRON_LOGROTATE)


def _name_log_daemon(persona: str, rng: secrets.SystemRandom) -> str:
    return rng.choice(_DAEMON_LOGROTATE)


def _name_cache_tmp(persona: str, rng: secrets.SystemRandom) -> str:
    # mkstemp shape: /tmp/.cache-XXXXXX with random alphanumerics.
    # Hidden dot keeps it out of `ls` by default — same as glibc/python.
    # Bandit B108 fires on the literal "/tmp/" path; suppressed at the
    # site because this is a path we are *generating for a target
    # decky*, not a file we are opening on the host.
    return f"/tmp/.cache-{_random_token(rng, 6)}"  # nosec B108


# ── Email + canary placeholders ────────────────────────────────────────────
# Email "names" (paths) are produced by the email driver's spool logic,
# not by realism naming. Canary paths are advisory — operators usually
# specify ``placement_path`` directly. Stage 7 of the realism migration
# refines canary placement based on persona + content_class.


def _name_email(persona: str, rng: secrets.SystemRandom) -> str:
    raise NotImplementedError(
        "email paths come from the email driver's spool logic, not "
        "realism.naming"
    )


def _name_canary(persona: str, rng: secrets.SystemRandom) -> str:
    raise NotImplementedError(
        "canary placement is set by the canary cultivator (stage 7), "
        "not realism.naming"
    )


# ── Dispatch ───────────────────────────────────────────────────────────────


_NAMERS: dict[ContentClass, Callable[[str, secrets.SystemRandom], str]] = {
    ContentClass.NOTE: _name_note,
    ContentClass.TODO: _name_todo,
    ContentClass.DRAFT: _name_draft,
    ContentClass.SCRIPT: _name_script,
    ContentClass.LOG_CRON: _name_log_cron,
    ContentClass.LOG_DAEMON: _name_log_daemon,
    ContentClass.CACHE_TMP: _name_cache_tmp,
    ContentClass.EMAIL: _name_email,
    ContentClass.CANARY_AWS_CREDS: _name_canary,
    ContentClass.CANARY_ENV_FILE: _name_canary,
    ContentClass.CANARY_GIT_CONFIG: _name_canary,
    ContentClass.CANARY_SSH_KEY: _name_canary,
    ContentClass.CANARY_HONEYDOC: _name_canary,
    ContentClass.CANARY_HONEYDOC_DOCX: _name_canary,
    ContentClass.CANARY_HONEYDOC_PDF: _name_canary,
    ContentClass.CANARY_MYSQL_DUMP: _name_canary,
    ContentClass.CANARY_FINGERPRINT_HTML: _name_canary,
    ContentClass.CANARY_FINGERPRINT_SVG: _name_canary,
}


def make_path(
    content_class: ContentClass,
    persona: str,
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> str:
    """Return a plausible absolute container-side path for *content_class*.

    Persona-conditioned for user-classes (``/home/<persona>/…``).
    System-classes ignore persona and pick from a logrotate-shaped
    skeleton.  Email and canary classes raise — those paths come
    from the respective drivers, not from realism naming.
    """
    rng = rand or secrets.SystemRandom()
    namer = _NAMERS.get(content_class)
    if namer is None:
        raise KeyError(
            f"no namer registered for content_class={content_class!r}"
        )
    return namer(persona, rng)
