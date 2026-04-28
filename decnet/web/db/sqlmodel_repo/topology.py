"""MazeNET topology: topologies, LANs, deckies, edges, status events,
and the live mutation queue.

This is the largest domain in the repo (~600 lines of methods).
Sections below correspond to the MazeNET dashboard panels.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import orjson
from sqlalchemy import asc, desc, func, select, text, update

from decnet.web.db.models import (
    LAN,
    Topology,
    TopologyDecky,
    TopologyEdge,
    TopologyMutation,
    TopologyStatusEvent,
)
from decnet.web.db.sqlmodel_repo._helpers import (
    _deserialize_json_fields,
    _serialize_json_fields,
)


class TopologyMixin:
    """Mixin: composed onto ``SQLModelRepository``."""

    # ─── topologies ────────────────────────────────────────────────────────

    async def create_topology(self, data: dict[str, Any]) -> str:
        payload = _serialize_json_fields(data, ("config_snapshot",))
        async with self._session() as session:
            row = Topology(**payload)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def get_topology(self, topology_id: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.id == topology_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            d = row.model_dump(mode="json")
            return _deserialize_json_fields(d, ("config_snapshot",))

    async def list_topologies(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[dict[str, Any]]:
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
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("config_snapshot",)
                )
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

    async def list_topologies_needing_resync(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(Topology).where(Topology.needs_resync == True)  # noqa: E712
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("config_snapshot",)
                )
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

    # ─── concurrency / pending-state guards ───────────────────────────────

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

    # ─── LANs ──────────────────────────────────────────────────────────────

    async def add_lan(
        self,
        data: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        async with self._session() as session:
            await self._check_and_bump_version(
                session, data["topology_id"], expected_version
            )
            row = LAN(**data)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def update_lan(
        self,
        lan_id: str,
        fields: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = False,
    ) -> None:
        if not fields:
            return
        async with self._session() as session:
            result = await session.execute(
                select(LAN).where(LAN.id == lan_id)
            )
            lan = result.scalar_one_or_none()
            if lan is None:
                raise ValueError(f"lan {lan_id!r} not found")
            if enforce_pending:
                await self._assert_pending(session, lan.topology_id)
            if expected_version is not None:
                await self._check_and_bump_version(
                    session, lan.topology_id, expected_version
                )
            await session.execute(
                update(LAN).where(LAN.id == lan_id).values(**fields)
            )
            await session.commit()

    async def delete_lan(
        self,
        lan_id: str,
        *,
        expected_version: Optional[int] = None,
    ) -> None:
        """Cascade-delete a LAN from a pending topology.

        Rejects if any decky declares this LAN as its home (i.e. has a
        non-bridge edge to it — the only LAN that decky lives in).  The
        caller must delete or reassign the home-deckies first.
        """
        from decnet.topology.status import TopologyNotEditable  # noqa: F401

        async with self._session() as session:
            result = await session.execute(select(LAN).where(LAN.id == lan_id))
            lan = result.scalar_one_or_none()
            if lan is None:
                return
            await self._assert_pending(session, lan.topology_id)

            # Home-decky check: any decky whose only edge lands here?
            edges_result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.lan_id == lan_id)
            )
            edges_here = edges_result.scalars().all()
            decky_uuids_on_this_lan = {e.decky_uuid for e in edges_here}
            for decky_uuid in decky_uuids_on_this_lan:
                other = await session.execute(
                    select(TopologyEdge).where(
                        TopologyEdge.decky_uuid == decky_uuid,
                        TopologyEdge.lan_id != lan_id,
                    )
                )
                if other.scalars().first() is None:
                    raise ValueError(
                        f"cannot delete LAN {lan.name!r}: decky "
                        f"{decky_uuid} has no other LAN (would be orphaned)"
                    )

            if expected_version is not None:
                await self._check_and_bump_version(
                    session, lan.topology_id, expected_version
                )
            # Cascade edges → LAN.
            await session.execute(
                text("DELETE FROM topology_edges WHERE lan_id = :l"),
                {"l": lan_id},
            )
            await session.execute(text("DELETE FROM lans WHERE id = :l"), {"l": lan_id})
            await session.commit()

    async def list_lans_for_topology(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(LAN).where(LAN.topology_id == topology_id).order_by(asc(LAN.name))
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    # ─── topology deckies ─────────────────────────────────────────────────

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

    # ─── topology edges ───────────────────────────────────────────────────

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
    ) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.id == edge_id)
            )
            edge = result.scalar_one_or_none()
            if edge is None:
                return
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
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(TopologyEdge).where(TopologyEdge.topology_id == topology_id)
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

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

    # ─── topology mutations (live reconciler queue) ──────────────────────

    async def enqueue_topology_mutation(
        self,
        topology_id: str,
        op: str,
        payload: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        """Append a pending mutation row and bump the topology version.

        Intended for use while the topology is ``active|degraded``; the
        reconciler picks these rows up on its next tick.
        """
        async with self._session() as session:
            await self._check_and_bump_version(
                session, topology_id, expected_version
            )
            row = TopologyMutation(
                topology_id=topology_id,
                op=op,
                payload=orjson.dumps(payload).decode(),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row.id

    async def claim_next_mutation(
        self, topology_id: str
    ) -> Optional[dict[str, Any]]:
        """Atomically claim the oldest pending mutation for ``topology_id``.

        Correctness-critical: this is ONE SQL statement.  Splitting it
        into SELECT-then-UPDATE would let two racing watch-loops both
        see the same ``pending`` row and both transition it to
        ``applying`` — double-executing the op.  With the single
        ``UPDATE ... WHERE id = (SELECT ... LIMIT 1) AND state='pending'``
        pattern the loser's UPDATE matches zero rows and returns
        ``None`` — that is the expected, non-error outcome under
        contention.
        """
        async with self._session() as session:
            now = datetime.now(timezone.utc).isoformat()
            # Single-statement atomic claim.  The inner SELECT picks the
            # oldest pending row; the outer UPDATE re-checks state so a
            # second racer that also saw that id finds state='applying'
            # and matches zero rows.
            # MySQL forbids referencing the UPDATE target inside a
            # subquery (ERROR 1093). Wrapping the inner SELECT in a
            # derived table forces materialisation and sidesteps the
            # rule. SQLite accepts both forms, so this stays portable.
            sql = text(
                """
                UPDATE topology_mutations
                SET state = 'applying'
                WHERE id = (
                    SELECT id FROM (
                        SELECT id FROM topology_mutations
                        WHERE topology_id = :t AND state = 'pending'
                        ORDER BY requested_at ASC
                        LIMIT 1
                    ) AS _next
                )
                AND state = 'pending'
                """
            )
            result = await session.execute(sql, {"t": topology_id})
            if result.rowcount == 0:
                await session.commit()
                return None
            # Re-read the row we just claimed.  The post-UPDATE SELECT is
            # safe: no racer can now transition an ``applying`` row back
            # to ``pending``.
            sel = await session.execute(
                select(TopologyMutation)
                .where(TopologyMutation.topology_id == topology_id)
                .where(TopologyMutation.state == "applying")
                .order_by(asc(TopologyMutation.requested_at))
                .limit(1)
            )
            row = sel.scalar_one_or_none()
            await session.commit()
            _ = now
            if row is None:
                return None
            return row.model_dump(mode="json")

    async def mark_mutation_applied(self, mutation_id: str) -> None:
        async with self._session() as session:
            await session.execute(
                text(
                    "UPDATE topology_mutations "
                    "SET state = 'applied', applied_at = :at "
                    "WHERE id = :i"
                ),
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "i": mutation_id,
                },
            )
            await session.commit()

    async def mark_mutation_failed(
        self, mutation_id: str, reason: str
    ) -> None:
        async with self._session() as session:
            await session.execute(
                text(
                    "UPDATE topology_mutations "
                    "SET state = 'failed', applied_at = :at, reason = :r "
                    "WHERE id = :i"
                ),
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "r": reason,
                    "i": mutation_id,
                },
            )
            await session.commit()

    async def list_topology_mutations(
        self,
        topology_id: str,
        state: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        async with self._session() as session:
            stmt = (
                select(TopologyMutation)
                .where(TopologyMutation.topology_id == topology_id)
                .order_by(desc(TopologyMutation.requested_at))
            )
            if state is not None:
                stmt = stmt.where(TopologyMutation.state == state)
            result = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def has_pending_topology_mutation(self) -> bool:
        """Cheap watch-loop guard: any pending mutation on a live topology?

        Uses the ``ix_topology_mutations_state_topology`` composite index
        to keep the join cheap at scale.  Returns False as soon as the
        reconciler path should be skipped.
        """
        async with self._session() as session:
            result = await session.execute(
                text(
                    "SELECT 1 FROM topology_mutations "
                    "WHERE state = 'pending' "
                    "AND topology_id IN ("
                    "    SELECT id FROM topologies "
                    "    WHERE status IN ('active', 'degraded')"
                    ") LIMIT 1"
                )
            )
            return result.first() is not None

    async def list_live_topology_ids(self) -> list[str]:
        """Return ids of topologies currently in ``active|degraded``."""
        async with self._session() as session:
            result = await session.execute(
                select(Topology.id).where(
                    Topology.status.in_(["active", "degraded"])
                )
            )
            return [r for r in result.scalars().all()]

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
