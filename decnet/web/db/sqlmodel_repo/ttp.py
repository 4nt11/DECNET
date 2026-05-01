"""TTP-tagging repository — ``ttp_tag`` reads + idempotent inserts.

Implementation phase E.3.3 of ``development/TTP_TAGGING.md``. The
shape was pinned at E.1.10; this file fills in the bodies.

Dialect-split convention: portable rollup queries live here on the
mixin; the bulk-insert "ignore on duplicate" hook lands in the
per-dialect ``SQLiteRepository`` / ``MySQLRepository`` subclasses
(``decnet/web/db/sqlite/repository.py`` /
``decnet/web/db/mysql/repository.py``) where the actual
``ON CONFLICT DO NOTHING`` vs ``INSERT IGNORE`` SQL diverges.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlmodel import col

from decnet.web.db.models import (
    Attacker,
    AttackerIdentity,
    CampaignTechniqueRow,
    IdentityTechniqueRow,
    TechniqueRollupRow,
    TTPTag,
)
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


# Confidence floor: tags computed below this value are silently dropped
# at insert time. Pinned by tests/ttp/test_confidence.py.
_CONFIDENCE_FLOOR: float = 0.3


class TTPMixin(_MixinBase):
    """Mixin: TTP-tag query + insert methods composed onto
    :class:`SQLModelRepository`.

    Expects ``self._session()`` from the base mixin and
    ``self._insert_tags_or_ignore()`` from the per-dialect repo.
    Adding a new ``ttp_tag`` query method here requires adding a
    contract test in ``tests/web/db/test_ttp_repo.py`` (E.2.13) AND a
    parametrized run against both SQLite and MySQL via the existing
    ``db_backends`` fixture.
    """

    async def _insert_tags_or_ignore(
        self, rows: list[TTPTag],
    ) -> int:
        """Dialect-specific bulk INSERT … ON CONFLICT DO NOTHING.

        Default body is the portable two-step (SELECT then ``add_all``)
        used as a safety-net; the SQLite + MySQL repositories override
        this with their native ``OR IGNORE`` / ``INSERT IGNORE`` SQL.
        """
        raise NotImplementedError(
            "_insert_tags_or_ignore is overridden in per-dialect repos",
        )

    async def insert_tags(self, rows: list[TTPTag]) -> int:
        """Bulk-upsert tags with ``INSERT OR IGNORE`` semantics.

        Drops rows with ``confidence < _CONFIDENCE_FLOOR`` (= 0.3) before
        the write. Returns the count of rows actually inserted (i.e. that
        passed the floor AND were not already present at their
        deterministic :func:`compute_tag_uuid` PK).
        """
        if not rows:
            return 0
        kept = [r for r in rows if r.confidence >= _CONFIDENCE_FLOOR]
        if not kept:
            return 0
        return await self._insert_tags_or_ignore(kept)

    async def list_techniques_by_identity(
        self,
        uuid: str,
    ) -> list[IdentityTechniqueRow]:
        """Per-Identity TTP rollup. Includes (a) tags directly anchored
        on this identity (``identity_uuid == uuid``) — covers identity-
        rollup tags with NULL ``attacker_uuid`` — and (b) tags anchored
        on an Attacker whose ``identity_id`` projects up to this
        identity (per-Attacker tags rolling up to the Identity).
        """
        async with self._session() as session:
            attacker_uuids_subq = (
                select(col(Attacker.uuid))
                .where(col(Attacker.identity_id) == uuid)
                .scalar_subquery()
            )
            stmt: Any = (
                select(
                    col(TTPTag.technique_id),
                    col(TTPTag.sub_technique_id),
                    func.max(col(TTPTag.tactic)).label("tactic"),
                    func.count().label("count"),
                    func.min(col(TTPTag.created_at)).label("first_seen"),
                    func.max(col(TTPTag.created_at)).label("last_seen"),
                    func.max(col(TTPTag.confidence)).label("confidence_max"),
                )
                .where(
                    (col(TTPTag.identity_uuid) == uuid)
                    | (col(TTPTag.attacker_uuid).in_(attacker_uuids_subq))
                )
                .group_by(TTPTag.technique_id, TTPTag.sub_technique_id)
            )
            res = await session.execute(stmt)
            return [
                IdentityTechniqueRow(
                    technique_id=r.technique_id,
                    sub_technique_id=r.sub_technique_id,
                    tactic=r.tactic,
                    count=r.count,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                    confidence_max=r.confidence_max,
                )
                for r in res.all()
            ]

    async def list_techniques_by_attacker(
        self,
        uuid: str,
    ) -> list[IdentityTechniqueRow]:
        """Per-Attacker (per-IP) TTP rollup. Identity-rollup tags
        (``attacker_uuid IS NULL``) are deliberately excluded — those
        belong to the Identity, not any one IP underneath it.
        """
        async with self._session() as session:
            stmt: Any = (
                select(
                    col(TTPTag.technique_id),
                    col(TTPTag.sub_technique_id),
                    func.max(col(TTPTag.tactic)).label("tactic"),
                    func.count().label("count"),
                    func.min(col(TTPTag.created_at)).label("first_seen"),
                    func.max(col(TTPTag.created_at)).label("last_seen"),
                    func.max(col(TTPTag.confidence)).label("confidence_max"),
                )
                .where(TTPTag.attacker_uuid == uuid)
                .group_by(TTPTag.technique_id, TTPTag.sub_technique_id)
            )
            res = await session.execute(stmt)
            return [
                IdentityTechniqueRow(
                    technique_id=r.technique_id,
                    sub_technique_id=r.sub_technique_id,
                    tactic=r.tactic,
                    count=r.count,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                    confidence_max=r.confidence_max,
                )
                for r in res.all()
            ]

    async def list_techniques_by_campaign(
        self,
        uuid: str,
    ) -> list[CampaignTechniqueRow]:
        """Campaign-wide TTP rollup. Joins ``ttp_tag.identity_uuid`` →
        :class:`AttackerIdentity` and filters on
        ``AttackerIdentity.campaign_id``. Note: the FK column is
        ``campaign_id``, not ``campaign_uuid``.
        """
        async with self._session() as session:
            stmt: Any = (
                select(
                    col(TTPTag.technique_id),
                    col(TTPTag.sub_technique_id),
                    func.max(col(TTPTag.tactic)).label("tactic"),
                    func.count().label("count"),
                    func.count(func.distinct(col(TTPTag.identity_uuid))).label(
                        "identity_count",
                    ),
                    func.max(col(TTPTag.created_at)).label("last_seen"),
                )
                .join(
                    AttackerIdentity,
                    AttackerIdentity.uuid == TTPTag.identity_uuid,
                )
                .where(AttackerIdentity.campaign_id == uuid)
                .group_by(TTPTag.technique_id, TTPTag.sub_technique_id)
            )
            res = await session.execute(stmt)
            return [
                CampaignTechniqueRow(
                    technique_id=r.technique_id,
                    sub_technique_id=r.sub_technique_id,
                    tactic=r.tactic,
                    count=r.count,
                    identity_count=r.identity_count,
                    last_seen=r.last_seen,
                )
                for r in res.all()
            ]

    async def list_techniques_by_session(
        self,
        sid: str,
    ) -> list[IdentityTechniqueRow]:
        """Session-scoped TTP timeline. Filtered on
        ``ttp_tag.session_id``.
        """
        async with self._session() as session:
            stmt: Any = (
                select(
                    col(TTPTag.technique_id),
                    col(TTPTag.sub_technique_id),
                    func.max(col(TTPTag.tactic)).label("tactic"),
                    func.count().label("count"),
                    func.min(col(TTPTag.created_at)).label("first_seen"),
                    func.max(col(TTPTag.created_at)).label("last_seen"),
                    func.max(col(TTPTag.confidence)).label("confidence_max"),
                )
                .where(TTPTag.session_id == sid)
                .group_by(TTPTag.technique_id, TTPTag.sub_technique_id)
            )
            res = await session.execute(stmt)
            return [
                IdentityTechniqueRow(
                    technique_id=r.technique_id,
                    sub_technique_id=r.sub_technique_id,
                    tactic=r.tactic,
                    count=r.count,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                    confidence_max=r.confidence_max,
                )
                for r in res.all()
            ]

    async def list_distinct_techniques(self) -> list[TechniqueRollupRow]:
        """Fleet-wide distinct-technique rollup with counts +
        most-recent-seen timestamps.
        """
        async with self._session() as session:
            stmt: Any = (
                select(
                    col(TTPTag.technique_id),
                    col(TTPTag.sub_technique_id),
                    func.max(col(TTPTag.tactic)).label("tactic"),
                    func.count().label("count"),
                    func.max(col(TTPTag.created_at)).label("last_seen"),
                )
                .group_by(TTPTag.technique_id, TTPTag.sub_technique_id)
            )
            res = await session.execute(stmt)
            return [
                TechniqueRollupRow(
                    technique_id=r.technique_id,
                    sub_technique_id=r.sub_technique_id,
                    tactic=r.tactic,
                    count=r.count,
                    last_seen=r.last_seen,
                )
                for r in res.all()
            ]
