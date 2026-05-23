# SPDX-License-Identifier: AGPL-3.0-or-later
"""DB-row + bus-topic helpers for the emailgen worker.

Mirror of :mod:`decnet.orchestrator.events` for the email action class.
Kept in its own module so the SSH-flavoured orchestrator and the
emailgen worker don't accumulate cross-imports of each other's action
types.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from decnet.bus import topics as _topics
from decnet.orchestrator.drivers.base import ActivityResult
from decnet.orchestrator.emailgen.scheduler import EmailAction


def to_row(action: EmailAction, result: ActivityResult) -> dict[str, Any]:
    """Build the kwargs dict for ``OrchestratorEmail(**...)``.

    Pulls ``message_id`` / ``subject`` / ``language`` out of the
    driver's ``payload`` rather than off the action — the EML's
    Message-ID is generated inside the driver after the LLM call so
    we know it matches what landed on disk.
    """
    payload = result.payload or {}
    return {
        "ts": datetime.now(timezone.utc),
        "mail_decky_uuid": action.mail_decky_uuid,
        "thread_id": action.thread_id,
        "message_id": payload.get("message_id", ""),
        "in_reply_to": action.parent_message_id,
        "sender_email": action.sender.email,
        "recipient_email": action.recipient.email,
        "subject": payload.get("subject", ""),
        "language": payload.get("language", action.sender.language or "en"),
        "eml_path": payload.get("eml_path", ""),
        "success": result.success,
        "payload": payload,    # repo serialises dict→json
    }


def topic_for(action: EmailAction) -> str:
    """Map an email action to its bus topic."""
    return _topics.orchestrator(_topics.ORCHESTRATOR_EMAIL, action.mail_decky_uuid)


def event_type_for(action: EmailAction) -> str:    # noqa: ARG001 — symmetry
    return _topics.ORCHESTRATOR_EMAIL
