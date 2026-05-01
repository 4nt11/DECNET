"""Tarpit rule CRUD."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select

from decnet.web.db.models import TarpitRule


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class TarpitMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def set_tarpit_rule(self, data: dict[str, Any]) -> None:
        """Upsert a tarpit rule keyed on ``decky_name`` (one rule per decky)."""
        async with self._session() as session:
            result = await session.execute(
                select(TarpitRule).where(TarpitRule.decky_name == data["decky_name"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                payload = {
                    "id": str(uuid.uuid4()),
                    "created_at": datetime.now(timezone.utc),
                    **data,
                }
                session.add(TarpitRule(**payload))
            await session.commit()

    async def get_tarpit_rule(self, decky_name: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TarpitRule).where(TarpitRule.decky_name == decky_name)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            d = row.model_dump(mode="json")
            d["ports"] = json.loads(d["ports"])
            return d

    async def delete_tarpit_rule(self, decky_name: str) -> bool:
        async with self._session() as session:
            result = await session.execute(
                select(TarpitRule).where(TarpitRule.decky_name == decky_name)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return False
            await session.delete(row)
            await session.commit()
            return True

    async def list_tarpit_rules(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(select(TarpitRule))
            rows = result.scalars().all()
            out = []
            for row in rows:
                d = row.model_dump(mode="json")
                d["ports"] = json.loads(d["ports"])
                out.append(d)
            return out
