"""Action picker for the emailgen worker.

One tick = one (mail-decky, sender, recipient, [thread]) decision.

Scope (v1):
- Only TopologyDeckies are eligible mail hosts. Fleet / SWARM-shard
  mail-deckies are out of scope per the plan; they get covered when the
  forwarder pattern lands for emailgen.
- Mail decky = a running TopologyDecky whose ``services`` includes
  ``imap`` or ``pop3``.
- Personas come from ``Topology.email_personas`` (JSON list of
  :class:`EmailPersona`).  Topology-wide ``language_default`` fills in
  any persona that didn't set its own.

Returns ``None`` (skip tick) when:
- no running mail decky,
- the mail decky's topology has fewer than two valid personas,
- nobody is in their ``active_hours`` window right now.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from decnet.logging import get_logger
from decnet.orchestrator.emailgen.threads import (
    ThreadChain,
    new_thread_id,
    references_for_reply,
    reply_subject,
)
from decnet.realism import personas_pool as global_pool
from decnet.realism.personas import (
    EmailPersona,
    in_active_hours,
    parse_personas,
)

logger = get_logger("orchestrator.emailgen")

_MAIL_SERVICES = ("imap", "pop3")
# Probability of replying on an existing thread when one exists.  The
# inverse starts a fresh thread.  0.6 mirrors what mailbox studies find
# for active corporate inboxes — most messages are replies, but not
# overwhelmingly so.
_REPLY_PROBABILITY = 0.6

# Generic context hints fed to the LLM when starting a new thread.
# Deliberately broad — the persona's tone + role is what shapes the
# email; the hint just gives the model a topic to riff on.
_CONTEXT_HINTS: tuple[str, ...] = (
    "Q3 budget review and approval",
    "Client presentation feedback",
    "Project deadline extension request",
    "Team building event planning",
    "IT system maintenance notification",
    "Quarterly performance review",
    "Vendor onboarding process",
    "Holiday schedule announcement",
    "Training session invitation",
    "Department restructuring update",
    "Client contract negotiation",
    "Security audit findings",
    "Sales strategy meeting",
    "Product launch timeline",
    "Office relocation update",
    "Travel reimbursement policy change",
)


@dataclass(frozen=True)
class EmailAction:
    """One emailgen tick's decision.

    ``thread_id`` is non-None whenever this action is a reply; the
    worker writes it back to the DB so future ticks can chain further
    replies.  ``in_reply_to`` / ``references`` mirror the RFC 2822
    headers we'll set on the EML.

    ``mail_decky_name`` / ``mail_decky_services`` are denormalised onto
    the action so the driver doesn't need a second repo round-trip just
    to resolve the container name.
    """
    mail_decky_uuid: str
    mail_decky_name: str
    mail_decky_services: tuple[str, ...]
    sender: EmailPersona
    recipient: EmailPersona
    thread_id: str
    parent_message_id: Optional[str]
    references: str
    subject_hint: Optional[str]      # used as parent subject when replying
    parent_excerpt: Optional[str]    # excerpt from the parent body
    context_hint: str                # only meaningful on new threads
    is_reply: bool
    description: str = "email:send"


def _is_mail_decky(decky: dict[str, Any]) -> bool:
    services = decky.get("services") or []
    if isinstance(services, str):
        return False
    return any(s in services for s in _MAIL_SERVICES)


async def _resolve_personas(
    repo: Any, mail_decky: dict[str, Any],
) -> tuple[list[EmailPersona], str]:
    """Pick the right persona source for *mail_decky* and return the list.

    Returns ``(personas, source_label)`` so logs can disambiguate why a
    tick was skipped.  Source label is the same string ``list_running_deckies``
    sets on the row (``"topology" | "fleet" | "shard"``) so the logger
    reads consistently against the rest of the orchestrator.

    Resolution rules (matches the design discussion):
    * **topology** source → walk to ``Topology.email_personas``; the
      topology owns its own list.  Each topology can have different
      personas.
    * **fleet** / **shard** source → unihost MACVLAN/IPVLAN deckies and
      SWARM shards have no parent topology row, so they share a single
      host-wide pool loaded from disk by :mod:`global_pool`.
    """
    source = mail_decky.get("source") or "unknown"
    if source == "topology":
        topology_id = mail_decky.get("topology_id")
        if not topology_id:
            return [], source
        topology = await repo.get_topology(topology_id)
        if not topology:
            return [], source
        if isinstance(topology, dict):
            raw = topology.get("email_personas")
            lang = topology.get("language_default") or "en"
        else:
            raw = topology.email_personas
            lang = topology.language_default or "en"
        return parse_personas(raw, language_default=lang), source
    # Fleet / shard / anything else → global pool.
    return global_pool.load(), source


async def pick(
    repo: Any,
    *,
    rand: Optional[secrets.SystemRandom] = None,
    now: Optional[datetime] = None,
) -> Optional[EmailAction]:
    """Pick one email action against any running mail decky.

    Mail-decky discovery uses the **union view** (``list_running_deckies``):
    MazeNET topology deckies, unihost fleet deckies, and SWARM shards are
    all eligible.  Persona source is per-decky-source; see
    :func:`_resolve_personas`.  *now* is the wall-clock used for
    ``active_hours`` filtering — injected so tests can pin the hour
    deterministically.
    """
    rng = rand or secrets.SystemRandom()
    now_dt = now or datetime.now()

    deckies = await repo.list_running_deckies()
    mail_deckies = [d for d in deckies if _is_mail_decky(d)]
    if not mail_deckies:
        logger.debug("emailgen pick: no running mail decky")
        return None

    mail_decky = rng.choice(mail_deckies)
    personas, source = await _resolve_personas(repo, mail_decky)
    if len(personas) < 2:
        logger.debug(
            "emailgen pick: source=%s mail_decky=%s only %d personas; need >=2",
            source, mail_decky.get("uuid"), len(personas),
        )
        return None

    active = [p for p in personas if in_active_hours(p, now_dt)]
    if len(active) < 2:
        logger.debug(
            "emailgen pick: source=%s mail_decky=%s only %d personas in-hours",
            source, mail_decky.get("uuid"), len(active),
        )
        return None

    sender = rng.choice(active)
    recipient = rng.choice([p for p in active if p.email != sender.email])

    # Look up open threads between this pair on this mail decky.
    chain = await _maybe_pick_chain(
        repo, mail_decky["uuid"], sender, recipient, rng=rng,
    )

    services = tuple(mail_decky.get("services") or ())
    decky_name = mail_decky.get("name") or ""

    if chain is not None:
        return EmailAction(
            mail_decky_uuid=mail_decky["uuid"],
            mail_decky_name=decky_name,
            mail_decky_services=services,
            sender=sender,
            recipient=recipient,
            thread_id=chain.thread_id,
            parent_message_id=chain.parent_message_id,
            references=references_for_reply(chain),
            subject_hint=chain.parent_subject,
            parent_excerpt=None,    # repo can populate later if useful
            context_hint=chain.parent_subject,
            is_reply=True,
        )

    return EmailAction(
        mail_decky_uuid=mail_decky["uuid"],
        mail_decky_name=decky_name,
        mail_decky_services=services,
        sender=sender,
        recipient=recipient,
        thread_id=new_thread_id(),
        parent_message_id=None,
        references="",
        subject_hint=None,
        parent_excerpt=None,
        context_hint=rng.choice(_CONTEXT_HINTS),
        is_reply=False,
    )


async def _maybe_pick_chain(
    repo: Any,
    mail_decky_uuid: str,
    sender: EmailPersona,
    recipient: EmailPersona,
    *,
    rng: secrets.SystemRandom,
) -> Optional[ThreadChain]:
    """Probabilistically pick an open thread between the pair, or None."""
    if rng.random() >= _REPLY_PROBABILITY:
        return None
    threads = await repo.list_orchestrator_email_threads(
        mail_decky_uuid, sender.email, recipient.email, limit=20,
    )
    if not threads:
        return None
    head = threads[0]
    return ThreadChain(
        thread_id=head["thread_id"],
        parent_message_id=head["message_id"],
        # We don't reconstruct the full ancestry from row history here —
        # the parent's References + parent's Message-ID would do that.
        # For v1, single-step references is fine; mail clients still
        # group correctly by (Subject + In-Reply-To).
        references=tuple(),
        parent_subject=reply_subject(head["subject"]),
    )
