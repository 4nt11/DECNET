"""GET /api/v1/orchestrator/events — paginated orchestrator activity.

Two underlying tables back this endpoint:

* ``orchestrator_events`` — SSH traffic + file ops (kind = ``traffic``, ``file``)
* ``orchestrator_emails`` — emailgen-generated EMLs (kind = ``email``)

When the caller filters ``kind=email`` we dispatch to the emails table
and adapt rows into the same wire shape the dashboard already renders.
The mapping is:

* ``action``           ← email subject
* ``src_decky_uuid``   ← sender_email
* ``dst_decky_uuid``   ← recipient_email
* ``protocol``         ← ``"smtp"``
* email-specific fields (``thread_id``, ``language``, ``mail_decky_uuid``,
  ``message_id``, ``in_reply_to``) ride along as top-level keys for the
  inspector / future per-email views; the existing event renderer
  ignores anything it doesn't recognise.

Mirrors :mod:`decnet.web.router.campaigns.api_list_campaigns`. The
orchestrator + emailgen workers are the sole writers; this surface is
read-only.
"""
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


def _adapt_email_row(e: dict[str, Any]) -> dict[str, Any]:
    """Reshape an ``orchestrator_emails`` row into the wire shape the
    dashboard's event table understands, while carrying the email-only
    fields through as extras."""
    return {
        "uuid": e.get("uuid"),
        "ts": e.get("ts"),
        "kind": "email",
        "protocol": "smtp",
        "action": e.get("subject", ""),
        "src_decky_uuid": e.get("sender_email"),
        "dst_decky_uuid": e.get("recipient_email"),
        "success": bool(e.get("success")),
        "payload": e.get("payload", "{}"),
        # Email-specific extras (renderer keys off ``kind == 'email'``).
        "subject": e.get("subject"),
        "sender_email": e.get("sender_email"),
        "recipient_email": e.get("recipient_email"),
        "language": e.get("language"),
        "thread_id": e.get("thread_id"),
        "mail_decky_uuid": e.get("mail_decky_uuid"),
        "message_id": e.get("message_id"),
        "in_reply_to": e.get("in_reply_to"),
    }


@router.get(
    "/orchestrator/events",
    tags=["Orchestrator"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.list_orchestrator_events")
async def list_orchestrator_events(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    kind: Optional[str] = Query(None, pattern="^(traffic|file|email)$"),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Paginated orchestrator-event list, newest first."""
    if kind == "email":
        emails = await repo.list_orchestrator_emails(limit=limit, offset=offset)
        total = await repo.count_orchestrator_emails()
        data = [_adapt_email_row(e) for e in emails]
    else:
        data = await repo.list_orchestrator_events(
            limit=limit, offset=offset, kind=kind,
        )
        total = await repo.count_orchestrator_events(kind=kind)
    return {"total": total, "limit": limit, "offset": offset, "data": data}
