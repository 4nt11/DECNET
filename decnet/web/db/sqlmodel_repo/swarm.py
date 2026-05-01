"""Swarm host CRUD."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import asc, select, text, update

from decnet.web.db.models import SwarmHost


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class SwarmMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``. Expects ``self._session()``."""

    async def add_swarm_host(self, data: dict[str, Any]) -> None:
        async with self._session() as session:
            session.add(SwarmHost(**data))
            await session.commit()

    async def get_swarm_host_by_name(self, name: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(select(SwarmHost).where(SwarmHost.name == name))
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def get_swarm_host_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(select(SwarmHost).where(SwarmHost.uuid == uuid))
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def get_swarm_host_by_fingerprint(self, fingerprint: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(SwarmHost).where(SwarmHost.client_cert_fingerprint == fingerprint)
            )
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def list_swarm_hosts(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        statement = select(SwarmHost).order_by(asc(SwarmHost.name))
        if status:
            statement = statement.where(SwarmHost.status == status)
        async with self._session() as session:
            result = await session.execute(statement)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def update_swarm_host(self, uuid: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        async with self._session() as session:
            await session.execute(
                update(SwarmHost).where(SwarmHost.uuid == uuid).values(**fields)
            )
            await session.commit()

    async def delete_swarm_host(self, uuid: str) -> bool:
        async with self._session() as session:
            # Clean up child shards first (no ON DELETE CASCADE portable across dialects).
            await session.execute(
                text("DELETE FROM decky_shards WHERE host_uuid = :u"), {"u": uuid}
            )
            result = await session.execute(
                select(SwarmHost).where(SwarmHost.uuid == uuid)
            )
            host = result.scalar_one_or_none()
            if not host:
                await session.commit()
                return False
            await session.delete(host)
            await session.commit()
            return True
