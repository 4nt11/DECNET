"""Live-reconciler mutation queue: enqueue + atomic claim + state writes."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import orjson
from sqlalchemy import asc, desc, select, text

from decnet.web.db.models import TopologyMutation


class TopologyMutationsMixin:
    """``self._check_and_bump_version`` resolves through
    ``TopologyCoreMixin`` via MRO."""

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
