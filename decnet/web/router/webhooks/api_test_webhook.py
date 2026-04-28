"""POST /webhooks/{uuid}/test — fire a synthetic ping to verify plumbing.

This hits the same delivery path the worker uses, so a 200 here proves
the destination URL, HMAC secret, and network egress all work without
waiting for a real bus event.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import WebhookTestResponse
from decnet.web.dependencies import repo, require_admin
from decnet.webhook.client import deliver, SyntheticEvent

log = get_logger("api.webhooks.test")

router = APIRouter()


@router.post(
    "/{uuid}/test",
    tags=["Webhooks"],
    response_model=WebhookTestResponse,
    responses={
        404: {"description": "Webhook not found"},
    },
)
@_traced("api.webhook.test")
async def api_test_webhook(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> WebhookTestResponse:
    sub = await repo.get_webhook_subscription(uuid)
    if not sub:
        raise HTTPException(status_code=404, detail="Webhook not found")

    event = SyntheticEvent(
        topic="test.ping",
        type="test",
        ts=datetime.now(timezone.utc).isoformat(),
        id=str(uuid4()),
        payload={
            "message": "Synthetic test event from DECNET",
            "triggered_by": admin.get("username", "unknown"),
        },
    )
    # Single attempt — no retries on manual tests. The operator wants a
    # fast signal about the current state of the receiver, not a
    # retry-and-wait behavior.
    result = await deliver(sub, event, retry_schedule=[])
    return WebhookTestResponse(
        delivered=result.ok,
        status_code=result.status_code,
        error=result.error,
    )
