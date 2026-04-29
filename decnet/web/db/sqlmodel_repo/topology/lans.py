"""LAN CRUD within a topology."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import asc, select, text, update

from decnet.web.db.models import LAN, TopologyEdge


class LansMixin:
    """``self._assert_pending`` / ``self._check_and_bump_version`` resolve
    through ``TopologyCoreMixin`` via MRO."""

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
        enforce_pending: bool = True,
    ) -> None:
        """Cascade-delete a LAN.

        Rejects if any decky declares this LAN as its home (i.e. has a
        non-bridge edge to it — the only LAN that decky lives in).  The
        caller must delete or reassign the home-deckies first.

        ``enforce_pending=True`` by default keeps the HTTP CRUD guard
        intact; the mutator's ``apply_remove_lan`` opts out (it has
        already gated on topology status and the live-LAN docker
        materialisation runs after).
        """
        from decnet.topology.status import TopologyNotEditable  # noqa: F401

        async with self._session() as session:
            result = await session.execute(select(LAN).where(LAN.id == lan_id))
            lan = result.scalar_one_or_none()
            if lan is None:
                return
            if enforce_pending:
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
