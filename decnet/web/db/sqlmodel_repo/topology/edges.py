"""Topology edge CRUD + status-event log."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import desc, select, text

from decnet.web.db.models import TopologyEdge, TopologyStatusEvent
from decnet.web.db.models.topology import EdgeRow


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class TopologyEdgesMixin(_MixinBase):
    """``self._assert_pending`` / ``self._check_and_bump_version`` resolve
    through ``TopologyCoreMixin`` via MRO."""

    async def add_topology_edge(
        self,
        data: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        async with self._session() as session:
            await self._check_and_bump_version(
                session, data["topology_id"], expected_version
            )
            row = TopologyEdge(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def delete_topology_edge(
        self,
        edge_id: str,
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = True,
    ) -> None:
        """Delete one edge.  ``enforce_pending=True`` by default — the
        mutator's ``apply_detach_decky`` opts out, same rationale as
        ``delete_topology_decky``.
        """
        async with self._session() as session:
            result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.id == edge_id)
            )
            edge = result.scalar_one_or_none()
            if edge is None:
                return
            if enforce_pending:
                await self._assert_pending(session, edge.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, edge.topology_id, expected_version
                )
            await session.execute(
                text("DELETE FROM topology_edges WHERE id = :e"),
                {"e": edge_id},
            )
            await session.commit()

    async def list_topology_edges(
        self, topology_id: str
    ) -> list[EdgeRow]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.topology_id == topology_id)
            )
            return [EdgeRow.model_validate(r.model_dump(mode="json")) for r in result.scalars().all()]

    async def list_topology_status_events(
        self, topology_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyStatusEvent)
                .where(TopologyStatusEvent.topology_id == topology_id)
                .order_by(desc(TopologyStatusEvent.at))
                .limit(limit)
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]
