"""Email lifter — SMTP message-level technique tagger.

Contract step E.1.6 of ``development/TTP_TAGGING.md``. Empty body.
Implementation phase parses message-level SMTP signal (headers,
attachment hashes, body sha) and emits Initial-Access / Phishing
techniques. PII discipline (design doc "Hard parts §6") is enforced at
the *type* layer: :class:`~decnet.web.db.models.ttp.EmailEvidence`
intentionally has no fields for raw rcpt addresses or body bytes, so
this lifter cannot leak them even by accident.
"""
from __future__ import annotations

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.web.db.models.ttp import TTPTag


class EmailLifter(TolerantTagger):
    name = "email"
    HANDLES = frozenset({"email"})

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        return []


__all__ = ["EmailLifter"]
