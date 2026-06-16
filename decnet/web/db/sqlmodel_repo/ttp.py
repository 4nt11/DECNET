# SPDX-License-Identifier: AGPL-3.0-or-later
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

import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, Optional

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
from decnet.web.db.models.canary import CanaryTrigger
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


def _technique_name(tid: str | None) -> str | None:
    from decnet.ttp.attack_catalog import technique_name  # heavy — lazy on first call
    return technique_name(tid)


def _mitre_url_for(tid: str | None) -> str | None:
    from decnet.ttp.attack_stix import mitre_url_for  # heavy — lazy on first call
    return mitre_url_for(tid)


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
                    technique_name=_technique_name(r.technique_id),
                    sub_technique_id=r.sub_technique_id,
                    sub_technique_name=_technique_name(r.sub_technique_id),
                    mitre_url=_mitre_url_for(r.sub_technique_id or r.technique_id),
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
                    technique_name=_technique_name(r.technique_id),
                    sub_technique_id=r.sub_technique_id,
                    sub_technique_name=_technique_name(r.sub_technique_id),
                    mitre_url=_mitre_url_for(r.sub_technique_id or r.technique_id),
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
                    technique_name=_technique_name(r.technique_id),
                    sub_technique_id=r.sub_technique_id,
                    sub_technique_name=_technique_name(r.sub_technique_id),
                    mitre_url=_mitre_url_for(r.sub_technique_id or r.technique_id),
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
                    technique_name=_technique_name(r.technique_id),
                    sub_technique_id=r.sub_technique_id,
                    sub_technique_name=_technique_name(r.sub_technique_id),
                    mitre_url=_mitre_url_for(r.sub_technique_id or r.technique_id),
                    tactic=r.tactic,
                    count=r.count,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                    confidence_max=r.confidence_max,
                )
                for r in res.all()
            ]

    async def list_ttp_decky_phases(
        self, identity_uuid: str,
    ) -> list[dict[str, Any]]:
        """Per-decky tag observations for the UKC bridge (E.3.15).

        Includes (a) tags directly anchored on this identity and
        (b) tags anchored on Attackers whose ``identity_id`` projects
        up to this identity — same scope as
        :meth:`list_techniques_by_identity`.
        """
        async with self._session() as session:
            attacker_uuids_subq = (
                select(col(Attacker.uuid))
                .where(col(Attacker.identity_id) == identity_uuid)
                .scalar_subquery()
            )
            stmt: Any = (
                select(
                    col(TTPTag.decky_id),
                    col(TTPTag.tactic),
                    col(TTPTag.created_at),
                )
                .where(
                    (
                        (col(TTPTag.identity_uuid) == identity_uuid)
                        | (col(TTPTag.attacker_uuid).in_(attacker_uuids_subq))
                    )
                    & (col(TTPTag.decky_id).is_not(None))
                )
                .order_by(col(TTPTag.created_at))
            )
            res = await session.execute(stmt)
            return [
                {
                    "decky_id": r.decky_id,
                    "tactic": r.tactic,
                    "created_at_ts": (
                        r.created_at.timestamp()
                        if r.created_at is not None else 0.0
                    ),
                }
                for r in res.all()
            ]

    async def list_tags_by_scope_and_technique(
        self,
        *,
        scope: str,
        uuid: str,
        technique_id: str,
        sub_technique_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return raw ``ttp_tag`` rows for a scope + technique pair.

        Powers the operator-facing inspector that explains *why* the
        rule engine flagged a technique. Three scopes:

        * ``scope="identity"`` — tags directly anchored on the identity
          AND tags on Attackers projecting up to the identity.
        * ``scope="attacker"`` — tags anchored on this attacker_uuid.
        * ``scope="session"`` — tags anchored on this session_id.

        Newest-first; capped at ``limit`` rows so a heavily-tagged
        attacker doesn't sink the inspector.
        """
        async with self._session() as session:
            stmt: Any = select(TTPTag)
            if scope == "identity":
                attacker_uuids_subq = (
                    select(col(Attacker.uuid))
                    .where(col(Attacker.identity_id) == uuid)
                    .scalar_subquery()
                )
                stmt = stmt.where(
                    (col(TTPTag.identity_uuid) == uuid)
                    | (col(TTPTag.attacker_uuid).in_(attacker_uuids_subq))
                )
            elif scope == "attacker":
                stmt = stmt.where(col(TTPTag.attacker_uuid) == uuid)
            elif scope == "session":
                stmt = stmt.where(col(TTPTag.session_id) == uuid)
            else:
                raise ValueError(f"unknown scope: {scope!r}")
            stmt = stmt.where(col(TTPTag.technique_id) == technique_id)
            if sub_technique_id is not None:
                stmt = stmt.where(
                    col(TTPTag.sub_technique_id) == sub_technique_id,
                )
            stmt = stmt.order_by(col(TTPTag.created_at).desc()).limit(limit)
            res = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in res.scalars().all()]

    async def list_ttp_tags_by_attacker(
        self, uuid: str, limit: int = 2000,
    ) -> list[dict]:
        """Raw ``ttp_tag`` rows for one attacker UUID. Newest-first.

        Used by the STIX exporter (and similar full-row consumers) that
        need per-tag granularity — distinct from the rollup returned by
        :meth:`list_techniques_by_attacker`.
        """
        async with self._session() as session:
            stmt: Any = (
                select(TTPTag)
                .where(TTPTag.attacker_uuid == uuid)
                .order_by(col(TTPTag.created_at).desc())
                .limit(limit)
            )
            res = await session.execute(stmt)
            return [r.model_dump(mode="json") for r in res.scalars().all()]

    async def get_all_ttp_rollups_for_export(self) -> dict[str, list[dict[str, Any]]]:
        """Return ``{attacker_uuid: [rollup_dict, ...]}`` for all attackers.

        Single query; used by the fleet STIX export so it doesn't fan out
        N × list_techniques_by_attacker calls.
        """
        async with self._session() as session:
            stmt: Any = (
                select(
                    col(TTPTag.attacker_uuid),
                    col(TTPTag.technique_id),
                    col(TTPTag.sub_technique_id),
                    func.max(col(TTPTag.tactic)).label("tactic"),
                    func.count().label("count"),
                    func.max(col(TTPTag.confidence)).label("confidence_max"),
                )
                .where(col(TTPTag.attacker_uuid).is_not(None))
                .group_by(
                    TTPTag.attacker_uuid,
                    TTPTag.technique_id,
                    TTPTag.sub_technique_id,
                )
            )
            res = await session.execute(stmt)
        out: dict[str, list[dict[str, Any]]] = {}
        for r in res.all():
            out.setdefault(r.attacker_uuid, []).append({
                "technique_id": r.technique_id,
                "sub_technique_id": r.sub_technique_id,
                "tactic": r.tactic,
                "count": r.count,
                "confidence_max": r.confidence_max,
            })
        return out

    # ── Backfill iterators (E.4) ────────────────────────────────────
    #
    # Read-only iterators consumed by ``decnet ttp backfill`` to replay
    # historical events through the live :class:`CompositeTagger`. The
    # CLI builds :class:`TaggerEvent` objects from these and persists
    # results via :meth:`insert_tags` — same idempotent path the bus
    # worker uses, no bus publish.
    #
    # Per TTP_TAGGING.md §"Order of work" / §"Bus topics" the historical
    # replay deliberately bypasses bus publish so SIEM/webhook fan-out
    # does not re-fire on already-attributed events.

    async def iter_attacker_commands_since(
        self, since: datetime,
    ) -> AsyncIterator[tuple[Attacker, list[dict[str, Any]]]]:
        """Yield ``(Attacker, decoded_commands)`` pairs since *since*.

        Walks every :class:`Attacker` whose ``last_seen >= since`` and
        decodes the JSON ``commands`` blob; non-list / malformed
        payloads are skipped silently (the JSON column is best-effort
        per the model docstring).
        """
        async with self._session() as session:
            stmt: Any = (
                select(Attacker).where(col(Attacker.last_seen) >= since)
            )
            res = await session.execute(stmt)
            for row in res.scalars().all():
                try:
                    decoded = json.loads(row.commands or "[]")
                except (ValueError, TypeError):
                    continue
                if not isinstance(decoded, list):
                    continue
                yield row, [c for c in decoded if isinstance(c, dict)]

    async def iter_canary_triggers_since(
        self, since: datetime,
    ) -> AsyncIterator[CanaryTrigger]:
        """Yield :class:`CanaryTrigger` rows fired since *since*."""
        async with self._session() as session:
            stmt: Any = (
                select(CanaryTrigger)
                .where(col(CanaryTrigger.occurred_at) >= since)
            )
            res = await session.execute(stmt)
            for row in res.scalars().all():
                yield row

    async def bump_attacker_ipv6_leak(
        self,
        attacker_uuid: str,
        identity_uuid: Optional[str],
        evidence: dict[str, Any],
    ) -> None:
        """Increment ``Attacker.ipv6_leak_count`` + set last_ipv6_* denorm fields.

        Also appends-with-dedup to ``AttackerIdentity.ipv6_link_local_iids``
        (JSON text column, keyed by ``addr``).  Both updates run in a single
        session; missing rows are silently skipped.
        """
        now = datetime.now(timezone.utc)
        addr = evidence.get("addr", "")
        async with self._session() as session:
            res = await session.execute(
                select(Attacker).where(Attacker.uuid == attacker_uuid)
            )
            attacker = res.scalar_one_or_none()
            if attacker is not None:
                attacker.ipv6_leak_count = (attacker.ipv6_leak_count or 0) + 1
                attacker.last_ipv6_leak_at = now
                attacker.last_ipv6_link_local = addr or None
                attacker.last_ipv6_iid_kind = evidence.get("iid_kind") or None
                attacker.last_ipv6_mac_oui = evidence.get("mac_oui") or None
                session.add(attacker)

            if identity_uuid:
                id_res = await session.execute(
                    select(AttackerIdentity).where(
                        AttackerIdentity.uuid == identity_uuid
                    )
                )
                identity = id_res.scalar_one_or_none()
                if identity is not None and addr:
                    try:
                        iids: list[dict[str, Any]] = json.loads(
                            identity.ipv6_link_local_iids or "[]"
                        )
                    except (json.JSONDecodeError, TypeError):
                        iids = []
                    if not any(e.get("iid") == addr for e in iids):
                        iids.append({
                            "iid": addr,
                            "oui": evidence.get("mac_oui", ""),
                            "kind": evidence.get("iid_kind", "unknown"),
                            "first_seen": now.isoformat(),
                        })
                        identity.ipv6_link_local_iids = json.dumps(iids)
                        session.add(identity)

            await session.commit()

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
                    technique_name=_technique_name(r.technique_id),
                    sub_technique_id=r.sub_technique_id,
                    sub_technique_name=_technique_name(r.sub_technique_id),
                    mitre_url=_mitre_url_for(r.sub_technique_id or r.technique_id),
                    tactic=r.tactic,
                    count=r.count,
                    last_seen=r.last_seen,
                )
                for r in res.all()
            ]
