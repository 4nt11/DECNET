# SPDX-License-Identifier: AGPL-3.0-or-later
"""Webhook subscription CRUD + delivery bookkeeping."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, update
from sqlmodel import col

from decnet.web.db.models import WebhookSubscription


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class WebhooksMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def create_webhook_subscription(self, data: dict[str, Any]) -> None:
        async with self._session() as session:
            session.add(WebhookSubscription(**data))
            await session.commit()

    async def get_webhook_subscription(
        self, uuid: str
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(WebhookSubscription).where(WebhookSubscription.uuid == uuid)
            )
            row = result.scalar_one_or_none()
            return row.model_dump() if row else None

    async def get_webhook_subscription_by_name(
        self, name: str
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(WebhookSubscription).where(WebhookSubscription.name == name)
            )
            row = result.scalar_one_or_none()
            return row.model_dump() if row else None

    async def list_webhook_subscriptions(
        self, enabled_only: bool = False
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(WebhookSubscription)
            if enabled_only:
                stmt = stmt.where(col(WebhookSubscription.enabled).is_(True))
            stmt = stmt.order_by(WebhookSubscription.created_at)
            result = await session.execute(stmt)
            return [r.model_dump() for r in result.scalars().all()]

    async def update_webhook_subscription(
        self, uuid: str, patch: dict[str, Any]
    ) -> bool:
        if not patch:
            return True
        patch = {**patch, "updated_at": datetime.now(timezone.utc)}
        async with self._session() as session:
            result = await session.execute(
                update(WebhookSubscription)
                .where(WebhookSubscription.uuid == uuid)
                .values(**patch)
            )
            await session.commit()
            return result.rowcount > 0

    async def delete_webhook_subscription(self, uuid: str) -> bool:
        async with self._session() as session:
            result = await session.execute(
                select(WebhookSubscription).where(WebhookSubscription.uuid == uuid)
            )
            row = result.scalar_one_or_none()
            if not row:
                return False
            await session.delete(row)
            await session.commit()
            return True

    async def record_webhook_success(
        self, uuid: str, ts: datetime
    ) -> None:
        async with self._session() as session:
            await session.execute(
                update(WebhookSubscription)
                .where(WebhookSubscription.uuid == uuid)
                .values(
                    consecutive_failures=0,
                    last_success_at=ts,
                    last_error=None,
                    updated_at=ts,
                )
            )
            await session.commit()

    async def record_webhook_failure(
        self, uuid: str, ts: datetime, error: str
    ) -> int:
        async with self._session() as session:
            # Read current failure count, bump, write. Small race window on
            # concurrent deliveries to the same subscription is acceptable —
            # the counter informs the circuit-breaker heuristic, not a
            # correctness invariant.
            result = await session.execute(
                select(col(WebhookSubscription.consecutive_failures)).where(
                    WebhookSubscription.uuid == uuid
                )
            )
            current = result.scalar_one_or_none() or 0
            new_count = current + 1
            await session.execute(
                update(WebhookSubscription)
                .where(WebhookSubscription.uuid == uuid)
                .values(
                    consecutive_failures=new_count,
                    last_failure_at=ts,
                    last_error=error[:512] if error else None,
                    updated_at=ts,
                )
            )
            await session.commit()
            return new_count

    async def trip_webhook_circuit(self, uuid: str, ts: datetime) -> None:
        async with self._session() as session:
            await session.execute(
                update(WebhookSubscription)
                .where(WebhookSubscription.uuid == uuid)
                .values(
                    enabled=False,
                    auto_disabled_at=ts,
                    updated_at=ts,
                )
            )
            await session.commit()
