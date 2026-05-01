"""Synthetic-file CRUD + realism config key/value store."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select, update

from decnet.web.db.models import RealismConfig, SyntheticFile
from decnet.web.db.models.realism import SYNTHETIC_FILE_BODY_LIMIT


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class RealismMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def record_synthetic_file(self, data: dict[str, Any]) -> str:
        if "last_body" in data and data["last_body"] is not None:
            data = {**data, "last_body": data["last_body"][:SYNTHETIC_FILE_BODY_LIMIT]}
        async with self._session() as session:
            row = SyntheticFile(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.uuid

    async def update_synthetic_file(
        self, row_uuid: str, data: dict[str, Any],
    ) -> None:
        if "last_body" in data and data["last_body"] is not None:
            data = {**data, "last_body": data["last_body"][:SYNTHETIC_FILE_BODY_LIMIT]}
        async with self._session() as session:
            stmt = (
                update(SyntheticFile)
                .where(SyntheticFile.uuid == row_uuid)
                .values(**data)
            )
            await session.execute(stmt)
            await session.commit()

    async def list_synthetic_files(
        self,
        *,
        decky_uuid: Optional[str] = None,
        persona: Optional[str] = None,
        content_class: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(SyntheticFile)
            if decky_uuid is not None:
                stmt = stmt.where(SyntheticFile.decky_uuid == decky_uuid)
            if persona is not None:
                stmt = stmt.where(SyntheticFile.persona == persona)
            if content_class is not None:
                stmt = stmt.where(SyntheticFile.content_class == content_class)
            stmt = (
                stmt.order_by(desc(SyntheticFile.last_modified))
                .offset(offset)
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def count_synthetic_files(
        self,
        *,
        decky_uuid: Optional[str] = None,
        persona: Optional[str] = None,
        content_class: Optional[str] = None,
    ) -> int:
        async with self._session() as session:
            stmt = select(func.count(SyntheticFile.uuid))
            if decky_uuid is not None:
                stmt = stmt.where(SyntheticFile.decky_uuid == decky_uuid)
            if persona is not None:
                stmt = stmt.where(SyntheticFile.persona == persona)
            if content_class is not None:
                stmt = stmt.where(SyntheticFile.content_class == content_class)
            result = await session.execute(stmt)
            return int(result.scalar() or 0)

    async def get_synthetic_file(
        self, uuid: str,
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(SyntheticFile).where(SyntheticFile.uuid == uuid)
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                return None
            return row.model_dump(mode="json")

    async def get_realism_config(
        self, key: str,
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            stmt = select(RealismConfig).where(RealismConfig.key == key)
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                return None
            return row.model_dump(mode="json")

    async def set_realism_config(
        self, key: str, value: str,
    ) -> None:
        """Upsert one realism_config row. Last-write-wins."""
        async with self._session() as session:
            stmt = select(RealismConfig).where(RealismConfig.key == key)
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                session.add(RealismConfig(
                    key=key, value=value,
                    updated_at=datetime.now(timezone.utc),
                ))
            else:
                upd = (
                    update(RealismConfig)
                    .where(RealismConfig.uuid == row.uuid)
                    .values(value=value, updated_at=datetime.now(timezone.utc))
                )
                await session.execute(upd)
            await session.commit()

    async def pick_random_synthetic_file_for_edit(
        self,
        decky_uuid: str,
        *,
        max_age_days: int = 30,
    ) -> Optional[dict[str, Any]]:
        # Editable classes: anything whose body is plain text we can
        # mutate idempotently. Binary canary artifacts are out — they
        # rotate via a fresh plant, not an edit.
        editable = (
            "note", "todo", "draft", "script", "log_cron", "log_daemon",
        )
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        async with self._session() as session:
            stmt = (
                select(SyntheticFile)
                .where(
                    SyntheticFile.decky_uuid == decky_uuid,
                    SyntheticFile.content_class.in_(editable),  # type: ignore[attr-defined]
                    SyntheticFile.last_modified >= cutoff,
                )
                # SQLite + MySQL both support func.random() / RAND() —
                # SQLAlchemy's func.random() compiles per-dialect.
                .order_by(func.random())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                return None
            return row.model_dump(mode="json")
