# SPDX-License-Identifier: AGPL-3.0-or-later
"""Orchestrator event log + email log + per-pool prune helpers."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import delete as sa_delete
from sqlalchemy import desc, func, or_, select
from sqlmodel import col

from decnet.web.db.models import OrchestratorEmail, OrchestratorEvent


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class OrchestratorMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def record_orchestrator_event(self, data: dict[str, Any]) -> str:
        payload = data.get("payload")
        if isinstance(payload, (dict, list)):
            data = {**data, "payload": json.dumps(payload)}
        async with self._session() as session:
            row = OrchestratorEvent(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.uuid

    async def list_orchestrator_events(
        self,
        limit: int = 100,
        offset: int = 0,
        *,
        kind: Optional[str] = None,
        since_ts: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(OrchestratorEvent)
            if kind is not None:
                stmt = stmt.where(OrchestratorEvent.kind == kind)
            if since_ts is not None:
                stmt = stmt.where(OrchestratorEvent.ts >= since_ts)
            stmt = (
                stmt.order_by(desc(OrchestratorEvent.ts))
                .offset(offset)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def count_orchestrator_events(
        self, *, kind: Optional[str] = None,
    ) -> int:
        stmt = select(func.count()).select_from(OrchestratorEvent)
        if kind is not None:
            stmt = stmt.where(OrchestratorEvent.kind == kind)
        async with self._session() as session:
            result = await session.execute(stmt)
            return result.scalar() or 0

    async def count_orchestrator_failures(
        self,
        *,
        since_ts: datetime,
        kind: Optional[str] = None,
    ) -> int:
        """Count failed orchestrator activity since *since_ts*, across
        both ``orchestrator_events`` (traffic / file) and
        ``orchestrator_emails`` (email).

        Backs the dashboard's failure-count badge — see DEBT-042. The
        in-memory window the badge previously computed against was
        bounded by the SSE-buffer + paginated page, so failures older
        than the local window read low. This is the authoritative count.
        """
        async with self._session() as session:
            ev_stmt = (
                select(func.count()).select_from(OrchestratorEvent)
                .where(
                    col(OrchestratorEvent.success).is_(False),
                    OrchestratorEvent.ts >= since_ts,
                )
            )
            if kind in ("traffic", "file"):
                ev_stmt = ev_stmt.where(OrchestratorEvent.kind == kind)
            em_stmt = (
                select(func.count()).select_from(OrchestratorEmail)
                .where(
                    col(OrchestratorEmail.success).is_(False),
                    OrchestratorEmail.ts >= since_ts,
                )
            )
            ev_count = 0
            em_count = 0
            if kind in (None, "traffic", "file"):
                ev_count = (await session.execute(ev_stmt)).scalar() or 0
            if kind in (None, "email"):
                em_count = (await session.execute(em_stmt)).scalar() or 0
            return ev_count + em_count

    async def prune_orchestrator_events(self, per_dst_cap: int = 10000) -> int:
        """Trim per-dst rows to *per_dst_cap*, oldest-first. Returns deleted count."""
        deleted = 0
        async with self._session() as session:
            dst_rows = await session.execute(
                select(col(OrchestratorEvent.dst_decky_uuid)).distinct()
            )
            for (dst,) in dst_rows.all():
                keep = await session.execute(
                    select(col(OrchestratorEvent.uuid))
                    .where(OrchestratorEvent.dst_decky_uuid == dst)
                    .order_by(desc(OrchestratorEvent.ts))
                    .limit(per_dst_cap)
                )
                keep_uuids = [u for (u,) in keep.all()]
                if not keep_uuids:
                    continue
                stmt = sa_delete(OrchestratorEvent).where(
                    OrchestratorEvent.dst_decky_uuid == dst,
                    col(OrchestratorEvent.uuid).notin_(keep_uuids),
                )
                res = await session.execute(stmt)
                deleted += res.rowcount or 0
            await session.commit()
        return deleted

    async def record_orchestrator_email(self, data: dict[str, Any]) -> str:
        payload = data.get("payload")
        if isinstance(payload, (dict, list)):
            data = {**data, "payload": json.dumps(payload)}
        async with self._session() as session:
            row = OrchestratorEmail(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.uuid

    async def list_orchestrator_emails(
        self,
        limit: int = 100,
        offset: int = 0,
        *,
        mail_decky_uuid: Optional[str] = None,
        thread_id: Optional[str] = None,
        since_ts: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(OrchestratorEmail)
            if mail_decky_uuid is not None:
                stmt = stmt.where(
                    OrchestratorEmail.mail_decky_uuid == mail_decky_uuid
                )
            if thread_id is not None:
                stmt = stmt.where(OrchestratorEmail.thread_id == thread_id)
            if since_ts is not None:
                stmt = stmt.where(OrchestratorEmail.ts >= since_ts)
            stmt = (
                stmt.order_by(desc(OrchestratorEmail.ts))
                .offset(offset)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def count_orchestrator_emails(
        self,
        *,
        mail_decky_uuid: Optional[str] = None,
    ) -> int:
        stmt = select(func.count()).select_from(OrchestratorEmail)
        if mail_decky_uuid is not None:
            stmt = stmt.where(OrchestratorEmail.mail_decky_uuid == mail_decky_uuid)
        async with self._session() as session:
            result = await session.execute(stmt)
            return result.scalar() or 0

    async def list_orchestrator_email_threads(
        self,
        mail_decky_uuid: str,
        sender_email: str,
        recipient_email: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        # Most-recent row per (sender, recipient) pair under this mail decky.
        # The scheduler only needs the latest message_id/subject/thread_id to
        # construct a reply; older rows in the same thread aren't relevant
        # for the "do we reply or start fresh" decision.
        async with self._session() as session:
            stmt = (
                select(OrchestratorEmail)
                .where(
                    OrchestratorEmail.mail_decky_uuid == mail_decky_uuid,
                    or_(
                        (OrchestratorEmail.sender_email == sender_email)
                        & (OrchestratorEmail.recipient_email == recipient_email),
                        (OrchestratorEmail.sender_email == recipient_email)
                        & (OrchestratorEmail.recipient_email == sender_email),
                    ),
                    col(OrchestratorEmail.success).is_(True),
                )
                .order_by(desc(OrchestratorEmail.ts))
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def prune_orchestrator_emails(self, per_decky_cap: int = 10000) -> int:
        """Trim per-mail-decky rows to *per_decky_cap*, oldest-first."""
        deleted = 0
        async with self._session() as session:
            decky_rows = await session.execute(
                select(col(OrchestratorEmail.mail_decky_uuid)).distinct()
            )
            for (mail_uuid,) in decky_rows.all():
                keep = await session.execute(
                    select(col(OrchestratorEmail.uuid))
                    .where(OrchestratorEmail.mail_decky_uuid == mail_uuid)
                    .order_by(desc(OrchestratorEmail.ts))
                    .limit(per_decky_cap)
                )
                keep_uuids = [u for (u,) in keep.all()]
                if not keep_uuids:
                    continue
                stmt = sa_delete(OrchestratorEmail).where(
                    OrchestratorEmail.mail_decky_uuid == mail_uuid,
                    col(OrchestratorEmail.uuid).notin_(keep_uuids),
                )
                res = await session.execute(stmt)
                deleted += res.rowcount or 0
            await session.commit()
        return deleted
