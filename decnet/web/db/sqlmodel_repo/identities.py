# SPDX-License-Identifier: AGPL-3.0-or-later
"""AttackerIdentity reads + writes.

Identity = the clustering output that groups multiple ``Attacker`` rows
(usually different IPs from the same actor) into one logical actor.
The identity-clusterer worker drives the writes; the dashboard drives
the reads.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select, update
from sqlmodel import col

from decnet.web.db.models import Attacker, AttackerIdentity


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class IdentitiesMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``.

    ``self._deserialize_attacker`` resolves through ``AttackersMixin``
    via MRO.
    """

    async def get_identity_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        # Follow merged_into_uuid up to the winner. Loop bounded by
        # _MAX_MERGE_HOPS so a (hypothetically) corrupted ring can't
        # spin the worker. Clusterer is responsible for never producing
        # a cycle; this guard is belt-and-braces.
        _MAX_MERGE_HOPS = 8
        async with self._session() as session:
            current_uuid = uuid
            for _ in range(_MAX_MERGE_HOPS):
                result = await session.execute(
                    select(AttackerIdentity).where(AttackerIdentity.uuid == current_uuid)
                )
                identity = result.scalar_one_or_none()
                if identity is None:
                    return None
                if identity.merged_into_uuid is None:
                    return identity.model_dump(mode="json")
                current_uuid = identity.merged_into_uuid
            # Hit the hop cap — surface what we have rather than recurse.
            return identity.model_dump(mode="json")

    async def list_identities(
        self, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        # Exclude merged-out rows so the list view is the de-duped truth.
        # The history is still queryable per-uuid via get_identity_by_uuid
        # and a future "merged into" endpoint when we need it.
        statement = (
            select(AttackerIdentity)
            .where(col(AttackerIdentity.merged_into_uuid).is_(None))
            .order_by(desc(AttackerIdentity.updated_at))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [i.model_dump(mode="json") for i in result.scalars().all()]

    async def count_identities(self) -> int:
        statement = (
            select(func.count())
            .select_from(AttackerIdentity)
            .where(col(AttackerIdentity.merged_into_uuid).is_(None))
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def list_observations_for_identity(
        self, identity_uuid: str, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        statement = (
            select(Attacker)
            .where(Attacker.identity_id == identity_uuid)
            .order_by(desc(Attacker.last_seen))
            .offset(offset)
            .limit(limit)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                self._deserialize_attacker(a.model_dump(mode="json"))
                for a in result.scalars().all()
            ]

    async def count_observations_for_identity(self, identity_uuid: str) -> int:
        statement = (
            select(func.count())
            .select_from(Attacker)
            .where(Attacker.identity_id == identity_uuid)
        )
        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def list_attackers_for_clustering(
        self, limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        # Project the columns the clusterer's similarity graph reads.
        # Keep it narrow so future denormalised projections (payloads
        # joined from logs, c2 endpoints aggregated from sessions) can
        # land here without churning every caller. ``fingerprints`` is
        # the raw JSON list — the clusterer parses for JA3 / HASSH.
        statement = select(  # type: ignore[call-overload]
            Attacker.uuid, Attacker.asn, Attacker.identity_id, Attacker.fingerprints,
        ).order_by(Attacker.first_seen)
        if limit is not None:
            statement = statement.limit(limit)
        async with self._session() as session:
            result = await session.execute(statement)
            return [
                {
                    "uuid": row.uuid,
                    "asn": row.asn,
                    "identity_id": row.identity_id,
                    "fingerprints": row.fingerprints,
                }
                for row in result.all()
            ]

    async def create_attacker_identity(self, row: dict[str, Any]) -> str:
        identity = AttackerIdentity(**row)
        async with self._session() as session:
            session.add(identity)
            await session.commit()
        return identity.uuid

    async def set_attacker_identity_id(
        self, attacker_uuid: str, identity_uuid: str,
    ) -> None:
        statement = (
            update(Attacker)
            .where(Attacker.uuid == attacker_uuid)
            .values(identity_id=identity_uuid)
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    async def list_all_identities(self) -> list[dict[str, Any]]:
        statement = select(AttackerIdentity).order_by(AttackerIdentity.created_at)
        async with self._session() as session:
            result = await session.execute(statement)
            return [i.model_dump(mode="json") for i in result.scalars().all()]

    async def update_identity_merged_into(
        self, identity_uuid: str, winner_uuid: Optional[str],
    ) -> None:
        statement = (
            update(AttackerIdentity)
            .where(AttackerIdentity.uuid == identity_uuid)
            .values(
                merged_into_uuid=winner_uuid,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()

    async def update_identity_fingerprints(
        self,
        identity_uuid: str,
        *,
        ja3_hashes: Optional[str] = None,
        hassh_hashes: Optional[str] = None,
        tls_cert_sha256: Optional[str] = None,
    ) -> None:
        statement = (
            update(AttackerIdentity)
            .where(AttackerIdentity.uuid == identity_uuid)
            .values(
                ja3_hashes=ja3_hashes,
                hassh_hashes=hassh_hashes,
                tls_cert_sha256=tls_cert_sha256,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async with self._session() as session:
            await session.execute(statement)
            await session.commit()
