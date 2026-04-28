"""RFC 2822 thread-chain bookkeeping.

A thread is a worker-side UUID that groups one or more emails between
the same two personas.  ``In-Reply-To`` carries the immediate parent's
``Message-ID``; ``References`` carries the full ancestry chain.

The emailgen scheduler queries the repository for the most recent email
in any thread between (sender, recipient); if it finds one, it emits a
reply (continuing the chain).  Otherwise it starts a new thread.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ThreadChain:
    """Immutable view of a thread's chain at a point in time.

    ``thread_id`` is opaque (UUID).  ``parent_message_id`` is the most
    recent message in the chain — the new reply's ``In-Reply-To`` field.
    ``references`` is the dot-separated history fed into the
    ``References:`` header (oldest-first per RFC 2822 §3.6.4).
    ``parent_subject`` carries the subject we're replying to, so the
    reply can prepend ``Re:`` correctly.
    """
    thread_id: str
    parent_message_id: str
    references: tuple[str, ...]
    parent_subject: str


def new_thread_id() -> str:
    return str(uuid.uuid4())


def reply_subject(parent_subject: str) -> str:
    """Prepend ``Re:`` to *parent_subject* if not already a reply.

    Folds repeat ``Re: Re: Re:`` into a single ``Re:`` — Outlook /
    Thunderbird both do this and an attacker reading the maildir would
    notice the corpus's missing convention immediately.
    """
    s = parent_subject.strip()
    lowered = s.lower()
    while lowered.startswith("re:"):
        s = s[3:].lstrip()
        lowered = s.lower()
    return f"Re: {s}"


def references_for_reply(chain: Optional[ThreadChain]) -> str:
    """Build the ``References:`` header value for a reply.

    Returns a space-separated list of message-ids, oldest-first, with
    the parent appended.  Empty string when *chain* is None (root).
    """
    if chain is None:
        return ""
    refs = list(chain.references) + [chain.parent_message_id]
    return " ".join(refs)


def new_message_id(domain: str) -> str:
    """Build an RFC 2822 ``Message-ID`` value (incl. angle brackets).

    Worker side — the value is also stored in the DB so a future reply
    can be threaded against it.  Domain mirrors the sender's email
    domain so an attacker grepping for tells doesn't find every
    fake-corp email tagged with ``@example.com``.
    """
    safe_domain = domain.strip() or "localhost"
    return f"<{uuid.uuid4().hex}@{safe_domain}>"
