# SPDX-License-Identifier: AGPL-3.0-or-later
"""Topology table CRUD + the optimistic-locking helpers that the
sibling LAN / decky / edge / mutation mixins call through MRO."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select, text

from decnet.web.db.models import Topology, TopologyStatusEvent
from decnet.web.db.models.topology import TopologySummary
from sqlmodel import col

from decnet.web.db.sqlmodel_repo._helpers import (
    _MixinBase,
    _serialize_json_fields
)


class TopologyCoreMixin(_MixinBase):
    """Topologies CRUD + ``_assert_pending`` / ``_check_and_bump_version``.

    The two private helpers live here because every other topology
    submixin (lans, deckies, edges, mutations) calls them through
    ``self.`` — MRO resolution lands them on this mixin no matter
    which submixin holds the caller.
    """

    async def create_topology(self, data: dict[str, Any]) -> str:
        payload = _serialize_json_fields(data, ("config_snapshot",))
        async with self._session() as session:
            row = Topology(**payload)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def get_topology(self, topology_id: str) -> Optional[TopologySummary]:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            return TopologySummary.model_validate(row.model_dump(mode="json"))

    async def list_topologies(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[TopologySummary]:
        statement = select(Topology).order_by(desc(Topology.created_at))
        if status:
            statement = statement.where(Topology.status == status)
        if offset is not None:
            statement = statement.offset(offset)
        if limit is not None:
            statement = statement.limit(limit)
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                TopologySummary.model_validate(r.model_dump(mode="json"))
                for r in result.scalars().all()
            ]

    async def count_topologies(self, status: Optional[str] = None) -> int:
        statement = select(func.count(Topology.id))
        if status:
            statement = statement.where(Topology.status == status)
        async with self._session() as session:
            result = await session.execute(statement)
            return int(result.scalar_one() or 0)

    async def update_topology_status(
        self,
        topology_id: str,
        new_status: str,
        reason: Optional[str] = None,
    ) -> None:
        """Update topology.status and append a TopologyStatusEvent atomically.

        Transition legality is enforced in ``decnet.topology.status``; this
        method trusts the caller.
        """
        now = datetime.now(timezone.utc)
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if topo is None:
                return
            from_status = topo.status
            topo.status = new_status
            topo.status_changed_at = now
            session.add(topo)
            session.add(
                TopologyStatusEvent(
                    topology_id=topology_id,
                    from_status=from_status,
                    to_status=new_status,
                    at=now,
                    reason=reason,
                )
            )
            await session.commit()

    async def set_topology_resync(self, topology_id: str, value: bool) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if topo is None:
                return
            topo.needs_resync = bool(value)
            session.add(topo)
            await session.commit()

    async def set_topology_email_personas(
        self, topology_id: str, personas_json: str,
    ) -> bool:
        """Replace ``Topology.email_personas`` with the supplied JSON.

        The string is stored as-is; validation/parsing is the caller's
        job (and is repeated by the emailgen scheduler each tick anyway).
        Returns True if a row was updated.
        """
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if topo is None:
                return False
            topo.email_personas = personas_json
            session.add(topo)
            await session.commit()
            return True

    async def list_topologies_needing_resync(self) -> list[TopologySummary]:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.needs_resync == True)  # noqa: E712
            )
            return [
                TopologySummary.model_validate(r.model_dump(mode="json"))
                for r in result.scalars().all()
            ]

    async def delete_topology_cascade(self, topology_id: str) -> bool:
        """Delete topology and all children.  No portable ON DELETE CASCADE."""
        async with self._session() as session:
            params = {"t": topology_id}
            await session.execute(
                text("DELETE FROM topology_status_events WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM topology_edges WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM topology_deckies WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM lans WHERE topology_id = :t"),
                params,
            )
            await session.execute(
                text("DELETE FROM topology_mutations WHERE topology_id = :t"),
                params,
            )
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            topo = result.scalar_one_or_none()
            if not topo:
                await session.commit()
                return False
            await session.delete(topo)
            await session.commit()
            return True

    async def list_live_topology_ids(self) -> list[str]:
        """Return ids of topologies currently in ``active|degraded``."""
        async with self._session() as session:
            result = await session.execute(
                select(col(Topology.id)).where(
                    col(Topology.status).in_(["active", "degraded"])
                )
            )
            return [r for r in result.scalars().all()]

    # ─── concurrency / pending-state guards (used by sibling mixins) ──────

    async def _assert_pending(self, session, topology_id: str) -> None:
        """Pre-deploy edits are pending-only.  Raises TopologyNotEditable."""
        from decnet.topology.status import TopologyNotEditable, TopologyStatus

        result = await session.execute(
            select(Topology).where(Topology.id == topology_id)
        )
        topo = result.scalar_one_or_none()
        if topo is None:
            raise ValueError(f"topology {topology_id!r} not found")
        if topo.status != TopologyStatus.PENDING:
            raise TopologyNotEditable(
                status=topo.status,
                reason="free-form edits are pending-only; use the "
                "mutator (topology_mutations) after deploy",
            )

    async def _check_and_bump_version(
        self,
        session,
        topology_id: str,
        expected_version: Optional[int],
    ) -> None:
        """Optimistic-concurrency guard used by child-row mutators.

        If ``expected_version`` is None, no check happens (backward-compat
        for internal callers that don't need concurrency protection).

        If supplied, loads the Topology row in the same session,
        compares ``version == expected_version``, raises VersionConflict
        on mismatch, otherwise bumps ``version += 1``.  The caller must
        commit the enclosing session.
        """
        from decnet.topology.status import VersionConflict

        if expected_version is None:
            return
        result = await session.execute(
            select(Topology).where(Topology.id == topology_id)
        )
        topo = result.scalar_one_or_none()
        if topo is None:
            raise ValueError(f"topology {topology_id!r} not found")
        if topo.version != expected_version:
            raise VersionConflict(
                current=topo.version, expected=expected_version
            )
        topo.version = topo.version + 1
        session.add(topo)
