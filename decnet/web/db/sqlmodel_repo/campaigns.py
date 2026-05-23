# SPDX-License-Identifier: AGPL-3.0-or-later
"""Campaign reads + writes.

Campaign = the second-tier clustering output that groups multiple
``AttackerIdentity`` rows into a coordinated activity cluster.  The
campaign-clusterer worker drives the writes; the dashboard drives
the reads.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select, update
from sqlmodel import col

from decnet.web.db.models import AttackerIdentity, Campaign


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class CampaignsMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def get_campaign_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        # Same chain-walk as get_identity_by_uuid; bounded against
        # corrupted rings.
        _MAX_MERGE_HOPS = 8
        async with self._session() as session:
            current_uuid = uuid
            for _ in range(_MAX_MERGE_HOPS):
                result = await session.execute(
                    select(Campaign).where(Campaign.uuid == current_uuid)
                )
                campaign = result.scalar_one_or_none()
                if campaign is None:
                    return None
                if campaign.merged_into_uuid is None:
                    return campaign.model_dump(mode="json")
                current_uuid = campaign.merged_into_uuid
            return campaign.model_dump(mode="json")

    async def list_campaigns(
        self, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(Campaign)
            .where(col(Campaign.merged_into_uuid).is_(None))
            .order_by(desc(Campaign.updated_at))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [c.model_dump(mode="json") for c in result.scalars().all()]

    async def count_campaigns(self) -> int:
        statement = (
            select(func.count())
            .select_from(Campaign)
            .where(col(Campaign.merged_into_uuid).is_(None))
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def list_identities_for_campaign(
        self, campaign_uuid: str, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(AttackerIdentity)
            .where(AttackerIdentity.campaign_id == campaign_uuid)
            .order_by(desc(AttackerIdentity.updated_at))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [i.model_dump(mode="json") for i in result.scalars().all()]

    async def count_identities_for_campaign(self, campaign_uuid: str) -> int:
        statement = (
            select(func.count())
            .select_from(AttackerIdentity)
            .where(AttackerIdentity.campaign_id == campaign_uuid)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def list_identities_for_clustering(
        self, limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        # Project the columns the campaign clusterer's similarity
        # graph reads. Narrow on purpose — future denormalised
        # projections (commands_by_phase from log mining, decky-set
        # aggregates) can land here without churning callers.
        statement = select(  # type: ignore[call-overload, misc]
            AttackerIdentity.uuid,
            AttackerIdentity.campaign_id,
            AttackerIdentity.merged_into_uuid,
            AttackerIdentity.first_seen_at,
            AttackerIdentity.last_seen_at,
            AttackerIdentity.ja3_hashes,
            AttackerIdentity.hassh_hashes,
            AttackerIdentity.payload_simhashes,
            AttackerIdentity.c2_endpoints,
        ).order_by(AttackerIdentity.created_at)
        if limit is not None:
            statement = statement.limit(limit)
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                {
                    "uuid": row.uuid,
                    "campaign_id": row.campaign_id,
                    "merged_into_uuid": row.merged_into_uuid,
                    "first_seen_at": (
                        row.first_seen_at.isoformat()
                        if row.first_seen_at is not None
                        else None
                    ),
                    "last_seen_at": (
                        row.last_seen_at.isoformat()
                        if row.last_seen_at is not None
                        else None
                    ),
                    "ja3_hashes": row.ja3_hashes,
                    "hassh_hashes": row.hassh_hashes,
                    "payload_simhashes": row.payload_simhashes,
                    "c2_endpoints": row.c2_endpoints,
                }
                for row in result.all()
            ]

    async def create_campaign(self, row: dict[str, Any]) -> str:
        campaign = Campaign(**row)
        async with self._session() as session:
            session.add(campaign)
            await session.commit()
        return campaign.uuid

    async def set_identity_campaign_id(
        self, identity_uuid: str, campaign_uuid: Optional[str],
    ) -> None:
        statement = (
            update(AttackerIdentity)
            .where(AttackerIdentity.uuid == identity_uuid)
            .values(
                campaign_id=campaign_uuid,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    async def list_all_campaigns(self) -> list[dict[str, Any]]:
        statement = select(Campaign).order_by(Campaign.created_at)
        async with self._session() as session:
            result = await session.execute(statement)
            return [c.model_dump(mode="json") for c in result.scalars().all()]

    async def update_campaign_merged_into(
        self, campaign_uuid: str, winner_uuid: Optional[str],
    ) -> None:
        statement = (
            update(Campaign)
            .where(Campaign.uuid == campaign_uuid)
            .values(
                merged_into_uuid=winner_uuid,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()
