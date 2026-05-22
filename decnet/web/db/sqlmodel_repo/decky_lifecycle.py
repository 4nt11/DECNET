"""DeckyLifecycle CRUD + sweep.

One row per (decky, operation) attempt.  States: pending → running →
succeeded | failed.  Mixed into ``SQLModelRepository`` for both SQLite
and MySQL via MRO composition.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import asc, select, update

from decnet.web.db.models import DeckyLifecycle
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


_TERMINAL = ("succeeded", "failed")


class LifecycleMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def create_lifecycle(self, data: dict[str, Any]) -> str:
        payload = dict(data)
        payload.setdefault("id", str(_uuid.uuid4()))
        payload.setdefault("status", "pending")
        now = datetime.now(timezone.utc)
        payload.setdefault("started_at", now)
        payload["updated_at"] = now
        async with self._session() as session:
            session.add(DeckyLifecycle(**payload))
            await session.commit()
        return str(payload["id"])

    async def update_lifecycle(
        self,
        lifecycle_id: str,
        fields: dict[str, Any],
    ) -> None:
        payload = dict(fields)
        payload["updated_at"] = datetime.now(timezone.utc)
        if payload.get("status") in _TERMINAL and "completed_at" not in payload:
            payload["completed_at"] = payload["updated_at"]
        async with self._session() as session:
            await session.execute(
                update(DeckyLifecycle)
                .where(DeckyLifecycle.id == lifecycle_id)
                .values(**payload)
            )
            await session.commit()

    async def get_lifecycle_by_ids(
        self, lifecycle_ids: list[str],
    ) -> list[dict[str, Any]]:
        if not lifecycle_ids:
            return []
        async with self._session() as session:
            result = await session.execute(
                select(DeckyLifecycle)
                .where(DeckyLifecycle.id.in_(lifecycle_ids))  # type: ignore[attr-defined]
                .order_by(asc(DeckyLifecycle.started_at))
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def find_open_lifecycle(
        self,
        decky_name: str,
        operation: str,
        host_uuid: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        stmt = (
            select(DeckyLifecycle)
            .where(DeckyLifecycle.decky_name == decky_name)
            .where(DeckyLifecycle.operation == operation)
            .where(DeckyLifecycle.status.in_(("pending", "running")))  # type: ignore[attr-defined]
            .order_by(DeckyLifecycle.started_at.desc())  # type: ignore[attr-defined]
        )
        if host_uuid is not None:
            stmt = stmt.where(DeckyLifecycle.host_uuid == host_uuid)
        async with self._session() as session:
            result = await session.execute(stmt)
            row = result.scalars().first()
            return row.model_dump(mode="json") if row else None

    async def sweep_stale_lifecycle(
        self,
        older_than: datetime,
        reason: str,
    ) -> int:
        now = datetime.now(timezone.utc)
        async with self._session() as session:
            result = await session.execute(
                update(DeckyLifecycle)
                .where(DeckyLifecycle.status.in_(("pending", "running")))  # type: ignore[attr-defined]
                .where(DeckyLifecycle.started_at < older_than)
                .values(
                    status="failed",
                    error=reason,
                    updated_at=now,
                    completed_at=now,
                )
            )
            await session.commit()
            return result.rowcount or 0
