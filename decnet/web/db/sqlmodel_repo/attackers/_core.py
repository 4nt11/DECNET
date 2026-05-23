# SPDX-License-Identifier: AGPL-3.0-or-later
"""Core ``Attacker`` row CRUD + the ``_deserialize_attacker`` helper.

The helper lives here because sibling submixins and ``IdentitiesMixin``
(``list_observations_for_identity``) both call it through ``self.`` —
MRO resolves them onto this mixin on the composed
``SQLModelRepository``.
"""
from __future__ import annotations

import json
import uuid as _uuid
from typing import Any, List, Optional

from sqlalchemy import desc, func, outerjoin, select
from sqlmodel import col

from decnet.web.db.models import Attacker, AttackerIntel


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class AttackersCoreMixin(_MixinBase):
    @staticmethod
    def _deserialize_attacker(d: dict[str, Any]) -> dict[str, Any]:
        for key in ("services", "deckies", "fingerprints", "commands"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    async def upsert_attacker(self, data: dict[str, Any]) -> str:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.ip == data["ip"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
                row_uuid = existing.uuid
            else:
                row_uuid = str(_uuid.uuid4())
                data = {**data, "uuid": row_uuid}
                session.add(Attacker(**data))
            await session.commit()
            return row_uuid

    async def get_attacker_uuid_by_ip(self, ip: str) -> Optional[str]:
        """Return the :class:`Attacker` UUID for *ip*, or ``None``.

        Used by the TTP worker to resolve ``attacker_uuid`` from the
        ``attacker_ip`` carried by collector-side bus events
        (``attacker.session.ended`` etc.). Cheaper than
        :meth:`get_attacker_by_uuid` because it scalars a single column.
        """
        async with self._session() as session:
            result = await session.execute(
                select(col(Attacker.uuid)).where(Attacker.ip == ip)
            )
            return result.scalar_one_or_none()

    async def get_attacker_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.uuid == uuid)
            )
            attacker = result.scalar_one_or_none()
            if not attacker:
                return None
            return self._deserialize_attacker(attacker.model_dump(mode="json"))

    async def get_attackers(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        sort_by: str = "recent",
        service: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        order: Any = {
            "active": desc(Attacker.event_count),
            "traversals": desc(Attacker.is_traversal),
        }.get(sort_by, desc(Attacker.last_seen))

        statement = select(Attacker).order_by(order).offset(offset).limit(limit)
        if search:
            statement = statement.where(col(Attacker.ip).like(f"%{search}%"))
        if service:
            statement = statement.where(col(Attacker.services).like(f'%"{service}"%'))

        async with self._session() as session:
            result = await session.execute(statement)
            return [
                self._deserialize_attacker(a.model_dump(mode="json"))
                for a in result.scalars().all()
            ]

    async def get_all_attackers_for_export(self) -> list[dict[str, Any]]:
        """Return every attacker row left-joined with its intel row.

        Used exclusively by the export endpoint — no pagination, ordered by
        last_seen desc so the file reads newest-first.
        """
        stmt = (
            select(Attacker, AttackerIntel)
            .select_from(
                outerjoin(Attacker, AttackerIntel, Attacker.uuid == AttackerIntel.attacker_uuid)
            )
            .order_by(desc(Attacker.last_seen))
        )
        async with self._session() as session:
            rows = (await session.execute(stmt)).all()

        result = []
        for attacker, intel in rows:
            d = self._deserialize_attacker(attacker.model_dump(mode="json"))
            d["threat_intel"] = intel.model_dump(mode="json") if intel is not None else None
            result.append(d)
        return result

    async def get_total_attackers(
        self, search: Optional[str] = None, service: Optional[str] = None
    ) -> int:
        statement = select(func.count()).select_from(Attacker)
        if search:
            statement = statement.where(col(Attacker.ip).like(f"%{search}%"))
        if service:
            statement = statement.where(col(Attacker.services).like(f'%"{service}"%'))

        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0
