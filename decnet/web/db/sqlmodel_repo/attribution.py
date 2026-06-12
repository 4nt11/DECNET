# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repo mixin for the ``attribution_state`` table + identity stub
materialisation.

Composed onto :class:`SQLModelRepository`. Five public methods, all
serving the v0 attribution engine
(``decnet.correlation.attribution_worker``):

* :meth:`ensure_stub_identity_for_attacker` — pre-clusterer 1:1 stub
  identity creation. Idempotent under concurrent observation bursts.
* :meth:`upsert_attribution_state` — keyed on
  ``(identity_uuid, primitive)``.
* :meth:`get_attribution_state` / :meth:`get_attribution_state_for_identity`
  — single-row and per-identity reads.
* :meth:`list_multi_actor_identities` — feeds the Phase 5 cross-
  primitive correlator.

See ``development/ATTRIBUTION-ENGINE.md`` for the full design.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Optional, cast

from sqlalchemy import func, select
from sqlmodel import col

from decnet.web.db.models import (
    Attacker,
    AttackerIdentity,
    AttributionStateRow,
)
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


class AttributionMixin(_MixinBase):
    """Mixin: methods composed onto :class:`SQLModelRepository`."""

    async def ensure_stub_identity_for_attacker(
        self, attacker_uuid: str,
    ) -> Optional[str]:
        """Return the ``identity_uuid`` for *attacker_uuid*, creating a
        degenerate 1:1 stub in ``attacker_identities`` if absent.

        Returns ``None`` when the Attacker row itself is missing — the
        attribution worker treats that as "defer" (mirrors the
        ``_handler.handle_session_ended`` posture in BEHAVE-SHELL).

        Idempotent: the second caller for the same attacker reads the
        ``identity_id`` stamped by the first caller and returns it
        without inserting again. Race: two concurrent first-callers
        could both see ``identity_id = NULL`` and both create stubs;
        the loser's commit would leave a dangling AttackerIdentity row
        with no Attacker referencing it. Acceptable in v0 (rare; rows
        are tiny; gc'd in v1 when the clusterer runs). The
        single-writer attribution worker plus the bus's per-identity
        ordering make even that race vanishingly rare in practice.
        """
        async with self._session() as session:
            attacker_row = (
                await session.execute(
                    select(Attacker).where(Attacker.uuid == attacker_uuid)
                )
            ).scalar_one_or_none()
            if attacker_row is None:
                return None
            if attacker_row.identity_id:
                return cast(str, attacker_row.identity_id)
            new_uuid = _uuid.uuid4().hex
            now = datetime.now(timezone.utc)
            session.add(
                AttackerIdentity(
                    uuid=new_uuid,
                    schema_version=1,
                    first_seen_at=attacker_row.first_seen,
                    last_seen_at=attacker_row.last_seen,
                    created_at=now,
                    updated_at=now,
                    observation_count=1,
                )
            )
            attacker_row.identity_id = new_uuid
            session.add(attacker_row)
            await session.commit()
            return new_uuid

    async def upsert_attribution_state(
        self, data: dict[str, Any],
    ) -> None:
        """Insert or update one ``(identity_uuid, primitive)`` row.

        ``data`` MUST carry: ``identity_uuid``, ``primitive``,
        ``current_value``, ``state``, ``confidence``,
        ``observation_count``, ``last_change_ts``,
        ``last_observation_ts``. ``schema_version`` and ``updated_at``
        are managed here.
        """
        identity_uuid = data["identity_uuid"]
        primitive = data["primitive"]
        async with self._session() as session:
            existing = (
                await session.execute(
                    select(AttributionStateRow).where(
                        AttributionStateRow.identity_uuid == identity_uuid,
                        AttributionStateRow.primitive == primitive,
                    )
                )
            ).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if existing is not None:
                for k, v in data.items():
                    if k in ("identity_uuid", "primitive"):
                        continue
                    setattr(existing, k, v)
                existing.updated_at = now
                session.add(existing)
            else:
                session.add(
                    AttributionStateRow(
                        **{**data, "schema_version": 1, "updated_at": now}
                    )
                )
            await session.commit()

    async def get_attribution_state(
        self, identity_uuid: str, primitive: str,
    ) -> Optional[dict[str, Any]]:
        """Single-row lookup. ``None`` when the merger has not yet run
        for this ``(identity_uuid, primitive)`` pair."""
        async with self._session() as session:
            row = (
                await session.execute(
                    select(AttributionStateRow).where(
                        AttributionStateRow.identity_uuid == identity_uuid,
                        AttributionStateRow.primitive == primitive,
                    )
                )
            ).scalar_one_or_none()
            return None if row is None else row.model_dump(mode="json")

    async def get_attribution_state_for_identity(
        self, identity_uuid: str,
    ) -> list[dict[str, Any]]:
        """All attribution-state rows for one identity, primitive-
        ordered for deterministic API output."""
        async with self._session() as session:
            rows = (
                await session.execute(
                    select(AttributionStateRow)
                    .where(AttributionStateRow.identity_uuid == identity_uuid)
                    .order_by(AttributionStateRow.primitive)
                )
            ).scalars().all()
            return [r.model_dump(mode="json") for r in rows]

    async def list_multi_actor_identities(
        self,
    ) -> list[dict[str, Any]]:
        """Identities with ≥ 2 primitives currently in ``multi_actor``.

        Output shape::

            [{"identity_uuid": "...", "primitives": ["motor.input_modality",
                                                     "cognitive.feedback_loop_engagement"]},
             ...]

        Empty list when no identity is co-flagged. Used by the Phase 5
        cross-primitive correlator — single-primitive ``multi_actor``
        is too noisy to alarm on, two independent primitives is the
        threshold for ``attribution.profile.multi_actor_suspected``.
        """
        async with self._session() as session:
            # First pass: identities with ≥ 2 multi_actor rows.
            count_stmt = (
                select(
                    col(AttributionStateRow.identity_uuid),
                    func.count().label("ct"),
                )
                .where(AttributionStateRow.state == "multi_actor")
                .group_by(col(AttributionStateRow.identity_uuid))
                .having(func.count() >= 2)
            )
            co_flagged = [
                row.identity_uuid
                for row in (await session.execute(count_stmt)).all()
            ]
            if not co_flagged:
                return []
            # Second pass: collect the primitive list per co-flagged
            # identity. Two queries beat one wide one because the
            # first query's count-having filter prunes the second
            # query's row set without a self-join.
            detail_stmt = (
                select(
                    col(AttributionStateRow.identity_uuid),
                    col(AttributionStateRow.primitive),
                )
                .where(
                    AttributionStateRow.state == "multi_actor",
                    col(AttributionStateRow.identity_uuid).in_(co_flagged),
                )
                .order_by(
                    col(AttributionStateRow.identity_uuid),
                    col(AttributionStateRow.primitive),
                )
            )
            grouped: dict[str, list[str]] = {}
            for row in (await session.execute(detail_stmt)).all():
                grouped.setdefault(row.identity_uuid, []).append(
                    row.primitive,
                )
            return [
                {"identity_uuid": iuuid, "primitives": prims}
                for iuuid, prims in grouped.items()
            ]
