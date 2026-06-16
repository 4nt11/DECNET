# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canary blob/token CRUD + trigger ingestion."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional, cast

from sqlalchemy import desc, func, select, update

from decnet.web.db.models import CanaryBlob, CanaryToken, CanaryTrigger


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class CanaryMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def upsert_canary_blob(self, data: dict[str, Any]) -> dict[str, Any]:
        sha = data.get("sha256")
        if not sha:
            raise ValueError("upsert_canary_blob: sha256 is required")
        async with self._session() as session:
            existing = await session.execute(
                select(CanaryBlob).where(CanaryBlob.sha256 == sha)
            )
            row = existing.scalar_one_or_none()
            if row:
                return cast(dict[str, Any], row.model_dump(mode="json"))
            row = CanaryBlob(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.model_dump(mode="json")

    async def get_canary_blob(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(CanaryBlob).where(CanaryBlob.uuid == uuid)
            )
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def get_canary_blob_by_sha256(
        self, sha256: str
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(CanaryBlob).where(CanaryBlob.sha256 == sha256)
            )
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def list_canary_blobs(self) -> list[dict[str, Any]]:
        # One round-trip: outer-join blobs -> tokens, group by blob, count
        # live (non-revoked) references.  Revoked tokens still occupy the
        # blob conceptually until garbage-collected, so we count them too;
        # the operator deletes blobs explicitly via the API.
        async with self._session() as session:
            stmt = (
                select(CanaryBlob, func.count(CanaryToken.uuid))
                .join(
                    CanaryToken,
                    CanaryToken.blob_uuid == CanaryBlob.uuid,
                    isouter=True,
                )
                .group_by(CanaryBlob.uuid)
                .order_by(desc(CanaryBlob.uploaded_at))
            )
            result = await session.execute(stmt)
            out: list[dict[str, Any]] = []
            for blob, count in result.all():
                d = blob.model_dump(mode="json")
                d["token_count"] = int(count or 0)
                out.append(d)
            return out

    async def delete_canary_blob(self, uuid: str) -> bool:
        async with self._session() as session:
            ref = await session.execute(
                select(func.count(CanaryToken.uuid)).where(
                    CanaryToken.blob_uuid == uuid
                )
            )
            if (ref.scalar_one() or 0) > 0:
                return False
            result = await session.execute(
                select(CanaryBlob).where(CanaryBlob.uuid == uuid)
            )
            row = result.scalar_one_or_none()
            if not row:
                return False
            await session.delete(row)
            await session.commit()
            return True

    async def create_canary_token(self, data: dict[str, Any]) -> None:
        async with self._session() as session:
            session.add(CanaryToken(**data))
            await session.commit()

    async def get_canary_token(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(CanaryToken).where(CanaryToken.uuid == uuid)
            )
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def get_canary_token_by_slug(
        self, callback_token: str
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(CanaryToken).where(
                    CanaryToken.callback_token == callback_token,
                    CanaryToken.state == "planted",
                )
            )
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def list_canary_tokens(
        self,
        *,
        decky_name: Optional[str] = None,
        state: Optional[str] = None,
        kind: Optional[str] = None,
        topology_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(CanaryToken)
            if decky_name is not None:
                stmt = stmt.where(CanaryToken.decky_name == decky_name)
            if state is not None:
                stmt = stmt.where(CanaryToken.state == state)
            if kind is not None:
                stmt = stmt.where(CanaryToken.kind == kind)
            if topology_id is not None:
                stmt = stmt.where(CanaryToken.topology_id == topology_id)
            stmt = stmt.order_by(desc(CanaryToken.placed_at))
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def update_canary_token_state(
        self,
        uuid: str,
        state: str,
        last_error: Optional[str] = None,
    ) -> bool:
        async with self._session() as session:
            result = await session.execute(
                update(CanaryToken)
                .where(CanaryToken.uuid == uuid)
                .values(state=state, last_error=last_error)
            )
            await session.commit()
            return cast(bool, result.rowcount > 0)

    async def record_canary_trigger(self, data: dict[str, Any]) -> str:
        # Persist the trigger row + bump the token's counters in the same
        # session so a subscriber that reads the token row right after
        # receiving the bus event sees the updated count.
        headers = data.get("raw_headers")
        if isinstance(headers, dict):
            data = {**data, "raw_headers": json.dumps(headers)}
        async with self._session() as session:
            row = CanaryTrigger(**data)
            session.add(row)
            ts = data.get("occurred_at") or datetime.now(timezone.utc)
            await session.execute(
                update(CanaryToken)
                .where(CanaryToken.uuid == row.token_uuid)
                .values(
                    last_triggered_at=ts,
                    trigger_count=CanaryToken.trigger_count + 1,
                )
            )
            await session.commit()
            await session.refresh(row)
            return row.uuid

    async def list_canary_triggers(
        self, token_uuid: str, *, limit: int = 100, offset: int = 0,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = (
                select(CanaryTrigger)
                .where(CanaryTrigger.token_uuid == token_uuid)
                .order_by(desc(CanaryTrigger.occurred_at))
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def attribute_canary_trigger(
        self, trigger_uuid: str, attacker_id: str,
    ) -> bool:
        async with self._session() as session:
            result = await session.execute(
                update(CanaryTrigger)
                .where(CanaryTrigger.uuid == trigger_uuid)
                .values(attacker_id=attacker_id)
            )
            await session.commit()
            return cast(bool, result.rowcount > 0)
