"""Persona schema for realism content generation.

Stored as a JSON list on :attr:`Topology.email_personas`.  Each persona
describes one fictional employee — sender of email *and* author of
files (notes, TODOs, drafts, scripts) on the deckies they're sampled
onto.  The schema deliberately stays narrow: the LLM gets *enough*
differentiation to write distinct voices, no more.

The class is still named :class:`EmailPersona` because every persona
in the pool today carries a mandatory email address (used for IMAP/
POP3 spool delivery).  Future per-decky personas without mailboxes
would justify a rename / superclass; not in scope for the realism
migration.

Invalid entries are dropped with a warning (returned alongside the
parsed list) rather than raising — a single typo in one persona must
not stall the entire realism tick.
"""
from __future__ import annotations

import json
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from decnet.logging import get_logger

logger = get_logger("realism.personas")

Tone = Literal["formal", "direct", "casual", "technical", "custom"]
ReplyLatency = Literal["fast", "normal", "slow"]


class EmailPersona(BaseModel):
    """One fake mailbox owner.

    ``language`` is ISO 639-1 (``en``, ``es``, ``pt``…); when unset on the
    persona it falls back to the topology's ``language_default``.
    ``uses_llms_heavily`` lifts the prompt-layer em-dash suppression for
    that persona — em-dashes are an LLM tell, but a persona explicitly
    pegged as a heavy LLM user should *naturally* produce them.
    """
    name: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=255)
    role: str = Field(min_length=1, max_length=128)
    tone: Tone = "formal"
    tone_custom: Optional[str] = Field(default=None, max_length=128)
    mannerisms: list[str] = Field(default_factory=list, max_length=12)
    language: Optional[str] = Field(default=None, max_length=8)
    signature: Optional[str] = Field(default=None, max_length=512)
    active_hours: str = Field(default="09:00-18:00", max_length=32)
    reply_latency: ReplyLatency = "normal"
    uses_llms_heavily: bool = False

    @model_validator(mode="after")
    def _custom_tone_requires_text(self) -> "EmailPersona":
        # ``tone="custom"`` lets operators describe a voice the four canned
        # tones don't capture (sarcastic, deadpan, terse, etc.).  The free
        # text is interpolated into the prompt verbatim, so an empty
        # value would just leave the LLM with the literal word "custom" —
        # reject it loudly instead of silently producing a useless prompt.
        if self.tone == "custom" and not (self.tone_custom and self.tone_custom.strip()):
            raise ValueError("tone_custom is required when tone is 'custom'")
        return self

    @field_validator("email")
    @classmethod
    def _email_shape(cls, v: str) -> str:
        # Cheap structural check — full RFC 5322 isn't worth the
        # dependency.  We only need ``user@domain`` with non-empty parts
        # for the prompt builder + Message-ID generator.
        if "@" not in v:
            raise ValueError("email must contain '@'")
        local, _, domain = v.rpartition("@")
        if not local or not domain or "." not in domain:
            raise ValueError("email must look like user@domain.tld")
        return v


def parse_personas(
    raw: str | list | None,
    *,
    language_default: str = "en",
) -> list[EmailPersona]:
    """Parse the JSON-or-list ``email_personas`` value into models.

    Resolves ``language`` against *language_default* so downstream
    consumers (prompt builder, scheduler) never need to know about
    fallback semantics.
    """
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("realism personas: invalid JSON, skipping: %s", exc)
            return []
    if not isinstance(raw, list):
        logger.warning(
            "realism personas: expected list, got %s", type(raw).__name__
        )
        return []
    out: list[EmailPersona] = []
    for i, entry in enumerate(raw):
        try:
            persona = EmailPersona.model_validate(entry)
        except ValidationError as exc:
            logger.warning(
                "realism personas: dropping invalid entry index=%d: %s",
                i, exc.errors(include_url=False),
            )
            continue
        if persona.language is None:
            persona = persona.model_copy(update={"language": language_default})
        out.append(persona)
    return out


def login_for(persona: str) -> str:
    """Return the linux login derived from a persona's display name.

    Lowercase, strip spaces; if the result isn't a plausible POSIX
    login (alnum ASCII), fall back to ``user`` so the path doesn't
    leak the persona's display name onto the decky filesystem.
    Shared by realism path naming (``decnet/realism/naming.py``) and
    canary cultivation (``decnet/canary/cultivator.py``).
    """
    candidate = persona.lower().replace(" ", "")
    if candidate.isalnum() and candidate.isascii() and candidate:
        return candidate
    return "user"


def in_active_hours(persona: EmailPersona, now_hour: int) -> bool:
    """Return True if *now_hour* (0–23) falls in the persona's window.

    Format: ``"HH:MM-HH:MM"``. Wrap-around windows (``"22:00-06:00"``)
    are supported. Invalid windows treat the persona as always-on so a
    config typo never silences the whole fleet.
    """
    try:
        start_s, end_s = persona.active_hours.split("-")
        start_h = int(start_s.split(":")[0])
        end_h = int(end_s.split(":")[0])
    except (ValueError, IndexError):
        return True
    if start_h == end_h:
        return True
    if start_h < end_h:
        return start_h <= now_hour < end_h
    # Wrap-around (e.g. 22:00-06:00).
    return now_hour >= start_h or now_hour < end_h
