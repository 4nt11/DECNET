# SPDX-License-Identifier: AGPL-3.0-or-later
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

import asyncio
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, Optional

from decnet.logging import get_logger
from decnet.realism.taxonomy import ContentClass

if TYPE_CHECKING:
    from decnet.realism.personas import EmailPersona

log = get_logger("realism.bodies")


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
    # All canary classes share one placeholder — content-class discriminant is the
    # "what"; the real payload (token slug, DNS hook URL) is injected by the canary
    # cultivator. Do not replace with distinct generators without updating cultivator.
    ContentClass.CANARY_AWS_CREDS: _body_canary,
    ContentClass.CANARY_ENV_FILE: _body_canary,
    ContentClass.CANARY_GIT_CONFIG: _body_canary,
    ContentClass.CANARY_SSH_KEY: _body_canary,
    ContentClass.CANARY_HONEYDOC: _body_canary,
    ContentClass.CANARY_HONEYDOC_DOCX: _body_canary,
    ContentClass.CANARY_HONEYDOC_PDF: _body_canary,
    ContentClass.CANARY_MYSQL_DUMP: _body_canary,
    ContentClass.CANARY_FINGERPRINT_HTML: _body_canary,
    ContentClass.CANARY_FINGERPRINT_SVG: _body_canary,
}


def make_body(
    content_class: ContentClass,
    persona: str,
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> str:
    """Return deterministic body bytes (utf-8 string) for *content_class*.

    Stage 3 ships templates only.  :func:`make_body_with_llm` is the
    LLM-aware variant added in stage 6 — kept on a separate name so
    the deterministic path stays trivially callable from tests and
    from the LLM fallback itself.
    """
    rng = rand or secrets.SystemRandom()
    gen = _BODIES.get(content_class)
    if gen is None:
        raise KeyError(
            f"no body generator registered for content_class={content_class!r}"
        )
    return gen(persona, rng)


async def make_body_with_llm(
    content_class: ContentClass,
    persona: "EmailPersona",
    *,
    llm=None,  # LLMBackend | None
    breaker=None,  # LLMCircuitBreaker | None
    timeout: float = 60.0,
    rand: Optional[secrets.SystemRandom] = None,
) -> str:
    """LLM-enriched body for user-classes; deterministic fallback otherwise.

    Falls back to :func:`make_body` whenever:

    * ``llm`` is None,
    * ``breaker.allow_call()`` returns False (sustained failure),
    * the LLM call times out or returns empty,
    * the content class isn't a user-class (system-class content
      should look formulaic, so we never invoke LLM there).

    Em-dash stripping runs on the LLM output as a belt-and-braces
    guard (see :mod:`decnet.realism.prompts._style`).  The function
    is async because LLM calls are; the deterministic path returns
    immediately so the orchestrator's tick doesn't pay async overhead
    when LLM is disabled.
    """
    rng = rand or secrets.SystemRandom()

    # System / canary / email classes never touch the LLM.
    if not content_class.is_user_class():
        return make_body(content_class, persona.name, rand=rng)

    if llm is None or (breaker is not None and not breaker.allow_call()):
        return make_body(content_class, persona.name, rand=rng)

    # Lazy imports keep the prompt + style modules out of the
    # deterministic path's import graph.
    from decnet.realism.llm.base import LLMTimeout
    from decnet.realism.prompts import filebody as _filebody
    from decnet.realism.prompts._style import strip_em_dashes

    prompt = _filebody.build(content_class, persona)
    try:
        result = await asyncio.wait_for(llm.generate(prompt), timeout=timeout)
    except (LLMTimeout, asyncio.TimeoutError):
        log.debug("realism.bodies LLM timeout class=%s persona=%s",
                  content_class.value, persona.name)
        if breaker is not None:
            breaker.record_failure()
        return make_body(content_class, persona.name, rand=rng)
    except Exception as exc:  # noqa: BLE001
        log.warning("realism.bodies LLM error class=%s persona=%s: %s",
                    content_class.value, persona.name, exc)
        if breaker is not None:
            breaker.record_failure()
        return make_body(content_class, persona.name, rand=rng)

    if not result.success or not result.text.strip():
        if breaker is not None:
            breaker.record_failure()
        return make_body(content_class, persona.name, rand=rng)

    if breaker is not None:
        breaker.record_success()
    return strip_em_dashes(result.text.rstrip() + "\n", persona)


# ── Edit-in-place mutators ─────────────────────────────────────────────────
# Stage 3b: deterministic per-class mutations.  The contract: take the
# previous body bytes, return a plausible *next* iteration (append a
# line, flip a checkbox, fix a typo).  Append-only for logs; small
# in-place edits for user content.  LLM enrichment in stage 6 wires
# next_iteration to ask "what would <persona> write next" with the
# previous body in the prompt; the deterministic path stays as the
# fallback.


def _edit_todo(
    prev: str, persona: str, rng: secrets.SystemRandom,
) -> str:
    """Flip an unchecked box, append a new item, or both.

    Real TODO files evolve: items get checked off as work happens, new
    items get added, occasionally a sub-bullet appears under an
    existing one.  We pick one of those mutations per call.
    """
    lines = prev.splitlines()
    unchecked_indices = [
        i for i, ln in enumerate(lines) if ln.startswith("- [ ]")
    ]
    op = rng.choice(("flip", "append", "both") if unchecked_indices else ("append",))
    if op in ("flip", "both") and unchecked_indices:
        idx = rng.choice(unchecked_indices)
        lines[idx] = lines[idx].replace("- [ ]", "- [x]", 1)
    if op in ("append", "both"):
        new_item = rng.choice(_TODO_VERBS)
        marker = "[x]" if rng.random() < 0.15 else "[ ]"
        lines.append(f"- {marker} {new_item}")
    return "\n".join(lines) + ("" if prev.endswith("\n") else "\n")


def _edit_note(
    prev: str, persona: str, rng: secrets.SystemRandom,
) -> str:
    """Append one new note line or insert a follow-up under an existing one."""
    new_line = rng.choice(_NOTE_TEMPLATES)
    if prev.endswith("\n"):
        return prev + new_line + "\n"
    return prev + "\n" + new_line + "\n"


def _edit_draft(
    prev: str, persona: str, rng: secrets.SystemRandom,
) -> str:
    """Append a new short paragraph to the existing draft."""
    addition = (
        "\nFollow-up: I'll send the deck once finance signs off on the numbers.\n",
        "\nP.S.: Looping in ops on the rollout sequence — they have context I don't.\n",
        "\nLet me know if any of this needs another pass.\n",
    )
    return prev.rstrip() + "\n" + rng.choice(addition)


def _edit_script(
    prev: str, persona: str, rng: secrets.SystemRandom,
) -> str:
    """Append a comment line — scripts evolve via comments and small fixes."""
    comments = (
        "# TODO: handle the empty-input case\n",
        "# 2026-04-27: hardened error path after the prod incident\n",
        "# noqa: shellcheck disagrees but this is what the runbook says\n",
    )
    return prev.rstrip() + "\n" + rng.choice(comments)


def _edit_log_cron(
    prev: str, persona: str, rng: secrets.SystemRandom,
) -> str:
    """Append one new cron syslog line — logs only ever grow."""
    extra = _body_log_cron(persona, rng)
    return prev.rstrip() + "\n" + extra.splitlines()[-1] + "\n"


def _edit_log_daemon(
    prev: str, persona: str, rng: secrets.SystemRandom,
) -> str:
    extra = _body_log_daemon(persona, rng)
    return prev.rstrip() + "\n" + extra.splitlines()[-1] + "\n"


_EDITORS: dict[ContentClass, Callable[[str, str, secrets.SystemRandom], str]] = {
    ContentClass.NOTE: _edit_note,
    ContentClass.TODO: _edit_todo,
    ContentClass.DRAFT: _edit_draft,
    ContentClass.SCRIPT: _edit_script,
    ContentClass.LOG_CRON: _edit_log_cron,
    ContentClass.LOG_DAEMON: _edit_log_daemon,
}


def next_iteration(
    content_class: ContentClass,
    persona: str,
    previous_body: str,
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> str:
    """Return the next-iteration body for an edit-in-place mutation.

    Raises :class:`KeyError` for content classes that don't support
    editing (canary blobs, cache-tmp scratch files, email).  The
    planner filters those out before producing an :class:`EditAction`,
    so reaching this branch with an unsupported class is a bug worth
    surfacing loudly.
    """
    rng = rand or secrets.SystemRandom()
    editor = _EDITORS.get(content_class)
    if editor is None:
        raise KeyError(
            f"content_class={content_class!r} does not support edits"
        )
    return editor(previous_body, persona, rng)
