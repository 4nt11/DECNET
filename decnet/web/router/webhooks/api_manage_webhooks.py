"""Webhook subscription CRUD — admin-gated."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.bus import topics as _topics
from decnet.bus.app import get_app_bus
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import (
    MessageResponse,
    WebhookCreateRequest,
    WebhookCreateResponse,
    WebhookResponse,
    WebhookUpdateRequest,
)
from decnet.web.db.models.webhooks import _row_to_response_dict
from decnet.web.dependencies import repo, require_admin
from decnet.webhook.enums import merge_patterns

log = get_logger("api.webhooks")

router = APIRouter()


async def _notify_subscriptions_changed() -> None:
    """Publish `system.webhook.subscriptions_changed` on the bus.

    Fire-and-forget per the bus contract — a dropped signal is recoverable
    because the webhook worker also reloads on a slow timer as a fallback.
    """
    try:
        bus = await get_app_bus()
        if bus is None:
            return
        await bus.publish(
            _topics.WEBHOOK_SUBSCRIPTIONS_CHANGED,
            {},
            event_type="changed",
        )
    except Exception as e:  # noqa: BLE001 — bus failures must not break CRUD
        log.warning("webhook subscriptions-changed publish failed: %s", e)


def _row_to_response(row: dict[str, Any]) -> WebhookResponse:
    return WebhookResponse(**_row_to_response_dict(row))


@router.post(
    "/",
    tags=["Webhooks"],
    response_model=WebhookCreateResponse,
    status_code=201,
    responses={
        400: {"description": "At least one of simple_events / topic_patterns required"},
        409: {"description": "Name already in use"},
    },
)
@_traced("api.webhook.create")
async def api_create_webhook(
    req: WebhookCreateRequest,
    admin: dict = Depends(require_admin),
) -> WebhookCreateResponse:
    patterns = merge_patterns(req.simple_events, req.topic_patterns)
    if not patterns:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one simple_events entry or topic_patterns pattern.",
        )

    existing = await repo.get_webhook_subscription_by_name(req.name)
    if existing:
        raise HTTPException(status_code=409, detail="Webhook name already exists")

    # Auto-generate a URL-safe secret if the caller didn't provide one.
    # 32 bytes of os-entropy is the same ballpark as a CSRF token.
    secret = req.secret or secrets.token_urlsafe(32)

    now = datetime.now(timezone.utc)
    data = {
        "name": req.name,
        "url": str(req.url),
        "secret": secret,
        "topic_patterns": json.dumps(patterns),
        "enabled": req.enabled,
        "consecutive_failures": 0,
        "created_at": now,
        "updated_at": now,
    }
    await repo.create_webhook_subscription(data)
    row = await repo.get_webhook_subscription_by_name(req.name)
    if row is None:
        # Should never happen — the create just committed. Treat as 500
        # rather than silently masking a storage bug.
        raise HTTPException(status_code=500, detail="Webhook created but not retrievable")

    await _notify_subscriptions_changed()

    return WebhookCreateResponse(
        **_row_to_response_dict(row),
        secret=secret,
    )


@router.get(
    "/",
    tags=["Webhooks"],
    response_model=list[WebhookResponse],
)
@_traced("api.webhook.list")
async def api_list_webhooks(
    admin: dict = Depends(require_admin),
) -> list[WebhookResponse]:
    rows = await repo.list_webhook_subscriptions()
    return [_row_to_response(r) for r in rows]


@router.get(
    "/{uuid}",
    tags=["Webhooks"],
    response_model=WebhookResponse,
    responses={404: {"description": "Webhook not found"}},
)
@_traced("api.webhook.get")
async def api_get_webhook(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> WebhookResponse:
    row = await repo.get_webhook_subscription(uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _row_to_response(row)


@router.patch(
    "/{uuid}",
    tags=["Webhooks"],
    response_model=WebhookResponse,
    responses={
        400: {"description": "Empty or invalid patch"},
        404: {"description": "Webhook not found"},
        409: {"description": "Name already in use"},
    },
)
@_traced("api.webhook.update")
async def api_update_webhook(
    uuid: str,
    req: WebhookUpdateRequest,
    admin: dict = Depends(require_admin),
) -> WebhookResponse:
    current = await repo.get_webhook_subscription(uuid)
    if not current:
        raise HTTPException(status_code=404, detail="Webhook not found")

    patch: dict[str, Any] = {}

    if req.name is not None and req.name != current["name"]:
        clash = await repo.get_webhook_subscription_by_name(req.name)
        if clash and clash["uuid"] != uuid:
            raise HTTPException(status_code=409, detail="Webhook name already exists")
        patch["name"] = req.name

    if req.url is not None:
        patch["url"] = str(req.url)

    if req.secret is not None:
        patch["secret"] = req.secret

    if req.enabled is not None:
        patch["enabled"] = req.enabled

    if req.simple_events is not None or req.topic_patterns is not None:
        # Re-merge using whatever the caller supplied; a caller that wants
        # to clear all patterns must explicitly pass both as empty lists.
        simple = req.simple_events if req.simple_events is not None else []
        raw = req.topic_patterns if req.topic_patterns is not None else []
        patterns = merge_patterns(simple, raw)
        if not patterns:
            raise HTTPException(
                status_code=400,
                detail="Cannot clear all patterns; disable the webhook instead.",
            )
        patch["topic_patterns"] = json.dumps(patterns)

    if not patch:
        # No-op patch — return the current row untouched.
        return _row_to_response(current)

    updated = await repo.update_webhook_subscription(uuid, patch)
    if not updated:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await _notify_subscriptions_changed()

    row = await repo.get_webhook_subscription(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _row_to_response(row)


@router.delete(
    "/{uuid}",
    tags=["Webhooks"],
    response_model=MessageResponse,
    responses={404: {"description": "Webhook not found"}},
)
@_traced("api.webhook.delete")
async def api_delete_webhook(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    deleted = await repo.delete_webhook_subscription(uuid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await _notify_subscriptions_changed()
    return {"message": "Webhook deleted"}
