"""Topology decky CRUD + the running-decky listing the fleet aggregator
calls through MRO."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import asc, select, text, update

from decnet.web.db.models import TopologyDecky
from decnet.web.db.sqlmodel_repo._helpers import (
    _deserialize_json_fields,
    _serialize_json_fields,
)


class TopologyDeckiesMixin:
    """``self._assert_pending`` / ``self._check_and_bump_version`` resolve
    through ``TopologyCoreMixin`` via MRO."""

    async def add_topology_decky(
        self,
        data: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        payload = _serialize_json_fields(data, ("services", "decky_config"))
        async with self._session() as session:
            await self._check_and_bump_version(
                session, data["topology_id"], expected_version
            )
            row = TopologyDecky(**payload)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.uuid

    async def update_topology_decky(
        self,
        decky_uuid: str,
        fields: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = False,
    ) -> None:
        if not fields:
            return
        payload = _serialize_json_fields(fields, ("services", "decky_config"))
        payload.setdefault("updated_at", datetime.now(timezone.utc))
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky).where(TopologyDecky.uuid == decky_uuid)
            )
            d = result.scalar_one_or_none()
            if d is None:
                raise ValueError(f"decky {decky_uuid!r} not found")
            if enforce_pending:
                await self._assert_pending(session, d.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, d.topology_id, expected_version
                )
            await session.execute(
                update(TopologyDecky)
                .where(TopologyDecky.uuid == decky_uuid)
                .values(**payload)
            )
            await session.commit()

    async def delete_topology_decky(
        self,
        decky_uuid: str,
        *,
        expected_version: Optional[int] = None,
    ) -> None:
        """Cascade-delete a decky + all its edges from a pending topology."""
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky).where(TopologyDecky.uuid == decky_uuid)
            )
            d = result.scalar_one_or_none()
            if d is None:
                return
            await self._assert_pending(session, d.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, d.topology_id, expected_version
                )
            await session.execute(
                text("DELETE FROM topology_edges WHERE decky_uuid = :u"),
                {"u": decky_uuid},
            )
            await session.execute(
                text("DELETE FROM topology_deckies WHERE uuid = :u"),
                {"u": decky_uuid},
            )
            await session.commit()

    async def list_topology_deckies(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky)
                .where(TopologyDecky.topology_id == topology_id)
                .order_by(asc(TopologyDecky.name))
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("services", "decky_config")
                )
                for r in result.scalars().all()
            ]

    async def list_running_topology_deckies(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyDecky).where(TopologyDecky.state == "running")
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("services", "decky_config")
                )
                for r in result.scalars().all()
            ]
