"""Per-content-class body generators (deterministic templates).

Stage 3 of the realism migration ships deterministic per-class
templates — varied enough that two notes on the same decky aren't
identical, formulaic enough that system-class files (cron logs,
journal entries) look like cron actually wrote them.

Stage 6 wires LLM enrichment for user-classes; the templates here
remain the fallback path so the orchestrator tick never blocks on
Ollama.

Determinism: every namer/body takes a :class:`SystemRandom` (from
:mod:`secrets`).  Tests pin the RNG seed for reproducibility; the
orchestrator passes a fresh RNG per tick so production picks are
unpredictable.

The factory mirrors :mod:`decnet.realism.naming`: caller passes a
:class:`~decnet.realism.taxonomy.ContentClass`; we return the body
generator registered for it.  Email + canary classes raise —
those bodies come from the email driver and canary cultivator
respectively, not from realism.bodies.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Callable, Optional

from decnet.realism.taxonomy import ContentClass


# ── User-class body generators ─────────────────────────────────────────────


_NOTE_TEMPLATES: tuple[str, ...] = (
    "follow up with the team on this",
    "remember to ping the on-call",
    "ask about the staging migration timeline",
    "double-check the runbook before next shift",
    "todo: rotate keys; check on backup task",
    "meeting notes from yesterday — copy onto wiki when free",
    "this is broken in prod; talk to ops monday",
    "draft response to the auditor — keep it short",
)


def _body_note(persona: str, rng: secrets.SystemRandom) -> str:
    n = rng.randint(2, 5)
    lines = rng.sample(_NOTE_TEMPLATES, k=min(n, len(_NOTE_TEMPLATES)))
    return "\n".join(lines) + "\n"


_TODO_VERBS: tuple[str, ...] = (
    "rotate keys", "review pr",
    "clean up logs", "update docs",
    "follow up on ticket",
    "test backup restore",
    "deploy to staging",
    "ack auditor email",
    "patch CVE backlog",
)


def _body_todo(persona: str, rng: secrets.SystemRandom) -> str:
    n = rng.randint(3, 7)
    items = rng.sample(_TODO_VERBS, k=min(n, len(_TODO_VERBS)))
    # Roughly a third pre-checked — looks like a list that's been
    # touched at least once.
    out = []
    for item in items:
        marker = "[x]" if rng.random() < 0.33 else "[ ]"
        out.append(f"- {marker} {item}")
    return "\n".join(out) + "\n"


_DRAFT_PARAGRAPHS: tuple[str, ...] = (
    "Hi team,\n\nQuick update on the project. We're tracking ahead of schedule "
    "on the migration but the staging soak revealed a regression in the "
    "auth path. I'll have a fix in by end of week.\n\nThanks,\n",
    "Hi,\n\nFollowing up on yesterday's meeting. Action items below:\n\n"
    "- Engineering owns the deployment plan\n"
    "- Ops will draft the runbook update\n"
    "- We sync again Friday\n\n",
    "All,\n\nProposal attached. Key points:\n\n"
    "1. We are not changing the data model in this release\n"
    "2. The new endpoint is opt-in via feature flag\n"
    "3. Rollback path is one config flip\n\n"
    "Feedback by EOD?\n\n",
)


def _body_draft(persona: str, rng: secrets.SystemRandom) -> str:
    return rng.choice(_DRAFT_PARAGRAPHS)


_SCRIPT_TEMPLATES: tuple[str, ...] = (
    "#!/usr/bin/env bash\nset -euo pipefail\n\n"
    "BACKUP_DIR=/var/backups\n"
    "STAMP=$(date +%Y%m%d-%H%M)\n"
    "echo \"backup start $STAMP\"\n"
    "tar czf \"$BACKUP_DIR/db-$STAMP.tar.gz\" /var/lib/mysql\n"
    "echo \"backup done\"\n",
    "#!/usr/bin/env bash\nset -e\n\n"
    "# clean up old logs\n"
    "find /var/log -name '*.log.*.gz' -mtime +30 -delete\n",
    "#!/usr/bin/env python3\n\"\"\"Quick fix for the reporting job.\"\"\"\n"
    "import sys\n\n"
    "def main():\n    print('todo: real fix here')\n\n"
    "if __name__ == '__main__':\n    sys.exit(main())\n",
)


def _body_script(persona: str, rng: secrets.SystemRandom) -> str:
    return rng.choice(_SCRIPT_TEMPLATES)


# ── System-class body generators ───────────────────────────────────────────


_CRON_COMMANDS: tuple[str, ...] = (
    "(root) CMD (run-parts /etc/cron.daily)",
    "(root) CMD (run-parts /etc/cron.hourly)",
    "(www-data) CMD (cd /var/www && /usr/bin/php artisan schedule:run)",
    "(backup) CMD (/usr/local/bin/backup.sh)",
    "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
)


def _body_log_cron(persona: str, rng: secrets.SystemRandom) -> str:
    n = rng.randint(8, 24)
    base = datetime.now(timezone.utc)
    lines = []
    for i in range(n):
        hour = (base.hour - i) % 24
        minute = rng.randint(0, 59)
        pid = rng.randint(1000, 99999)
        cmd = rng.choice(_CRON_COMMANDS)
        # ISO-ish "Apr 27 09:13:44 host CRON[1234]: ..." cron syslog shape.
        date_s = base.strftime("%b %d")
        lines.append(
            f"{date_s} {hour:02d}:{minute:02d}:{rng.randint(0,59):02d} "
            f"hostname CRON[{pid}]: {cmd}"
        )
    return "\n".join(lines) + "\n"


_DAEMON_LINES: tuple[str, ...] = (
    "systemd[1]: Started Daily apt download activities.",
    "systemd[1]: apt-daily.service: Succeeded.",
    "systemd[1]: Reached target Multi-User System.",
    "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=…",
    "sshd[2103]: pam_unix(sshd:session): session opened for user admin by (uid=0)",
    "sshd[2103]: Received disconnect from 10.0.0.4 port 47282:11: disconnected by user",
    "CRON[1894]: pam_unix(cron:session): session closed for user root",
)


def _body_log_daemon(persona: str, rng: secrets.SystemRandom) -> str:
    n = rng.randint(10, 30)
    lines = []
    base = datetime.now(timezone.utc)
    for _ in range(n):
        lines.append(
            f"{base.strftime('%b %d %H:%M:%S')} hostname "
            f"{rng.choice(_DAEMON_LINES)}"
        )
    return "\n".join(lines) + "\n"


def _body_cache_tmp(persona: str, rng: secrets.SystemRandom) -> str:
    # ~64-256 bytes of opaque session-ish payload — most /tmp/.cache-*
    # files in the wild are short binary or k=v dumps.  We emit ASCII
    # so docker exec write paths don't need binary-safety acrobatics.
    nbytes = rng.randint(64, 256)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "session=" + "".join(rng.choice(chars) for _ in range(nbytes)) + "\n"


def _body_email(persona: str, rng: secrets.SystemRandom) -> str:
    raise NotImplementedError(
        "email bodies come from the email driver, not realism.bodies"
    )


def _body_canary(persona: str, rng: secrets.SystemRandom) -> str:
    raise NotImplementedError(
        "canary bodies come from the canary cultivator (stage 7), "
        "not realism.bodies"
    )


# ── Dispatch ───────────────────────────────────────────────────────────────


_BODIES: dict[ContentClass, Callable[[str, secrets.SystemRandom], str]] = {
    ContentClass.NOTE: _body_note,
    ContentClass.TODO: _body_todo,
    ContentClass.DRAFT: _body_draft,
    ContentClass.SCRIPT: _body_script,
    ContentClass.LOG_CRON: _body_log_cron,
    ContentClass.LOG_DAEMON: _body_log_daemon,
    ContentClass.CACHE_TMP: _body_cache_tmp,
    ContentClass.EMAIL: _body_email,
    ContentClass.CANARY_AWS_CREDS: _body_canary,
    ContentClass.CANARY_ENV_FILE: _body_canary,
    ContentClass.CANARY_GIT_CONFIG: _body_canary,
    ContentClass.CANARY_SSH_KEY: _body_canary,
    ContentClass.CANARY_HONEYDOC: _body_canary,
    ContentClass.CANARY_HONEYDOC_DOCX: _body_canary,
    ContentClass.CANARY_HONEYDOC_PDF: _body_canary,
    ContentClass.CANARY_MYSQL_DUMP: _body_canary,
}


def make_body(
    content_class: ContentClass,
    persona: str,
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> str:
    """Return deterministic body bytes (utf-8 string) for *content_class*.

    Stage 3 ships templates only; stage 6 adds an optional
    ``LLMBackend`` parameter that, when supplied and the breaker is
    closed, replaces the template return for user-classes.
    """
    rng = rand or secrets.SystemRandom()
    gen = _BODIES.get(content_class)
    if gen is None:
        raise KeyError(
            f"no body generator registered for content_class={content_class!r}"
        )
    return gen(persona, rng)
