"""Repo mixin for the ``observations`` table.

Composed onto :class:`SQLModelRepository`. Three public methods:

* :meth:`upsert_observation` — idempotent on
  ``(evidence_ref, primitive)``. Caller passes the BEHAVE envelope as
  a dict plus the DECNET-side ``attacker_uuid`` denorm.
* :meth:`latest_observation_per_primitive` — backs the AttackerDetail
  "current state" panel. Implements the canonical query from
  ``BEHAVE-INTEGRATION.md`` §"Storage".
* :meth:`observations_time_series` — every observation of one
  primitive for one attacker, ordered ASC by ``ts``. Backs future
  drift charts.

PII discipline is the BEHAVE envelope's job
(``core/behave_core/spec/envelope.py:3-19``); this mixin does
not validate values — that happens at construction time by the BEHAVE
``Observation`` subclass before the dict reaches us.
"""
from __future__ import annotations

import uuid as _uuid
from typing import Any, Optional

from sqlalchemy import desc, func, select
from sqlmodel import col

from decnet.web.db.models import Attacker, ObservationRow
from decnet.web.db.sqlmodel_repo._helpers import _MixinBase


def _to_envelope(row: "ObservationRow") -> dict:
    """Map an ObservationRow to a BEHAVE envelope dict for STIX export."""
    d: dict = {
        "primitive": row.primitive,
        "value": row.value,
        "confidence": row.confidence,
        "window": {"start_ts": row.window_start_ts, "end_ts": row.window_end_ts},
        "source": row.source,
        "evidence_ref": row.evidence_ref,
    }
    if row.identity_ref is not None:
        d["identity_ref"] = row.identity_ref
    return d


class ObservationsMixin(_MixinBase):
    """Mixin: methods composed onto :class:`SQLModelRepository`."""

    async def upsert_observation(self, data: dict[str, Any]) -> str:
        """Insert or update an observation row keyed on
        ``(evidence_ref, primitive)``.

        ``data`` MUST carry every non-default ``ObservationRow`` field:
        ``primitive``, ``value``, ``confidence``, ``window_start_ts``,
        ``window_end_ts``, ``source``, ``evidence_ref``, ``envelope_v``,
        ``ts``, ``attacker_uuid``. ``id`` is generated if absent.
        ``identity_ref`` is optional.

        Returns the row's ``id``. Idempotent: a second call with the
        same ``(evidence_ref, primitive)`` overwrites the prior row's
        mutable fields (value, confidence, ts, etc.) without
        violating the unique constraint.
        """
        evidence_ref = data["evidence_ref"]
        primitive = data["primitive"]
        async with self._session() as session:
            stmt = select(ObservationRow).where(
                ObservationRow.evidence_ref == evidence_ref,
                ObservationRow.primitive == primitive,
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if existing:
                # Mutable fields from the new envelope; ``id`` and the
                # natural key stay locked to the existing row.
                for k, v in data.items():
                    if k in ("id", "evidence_ref", "primitive"):
                        continue
                    setattr(existing, k, v)
                session.add(existing)
                row_id = existing.id
            else:
                row_id = data.get("id") or _uuid.uuid4().hex
                row_data = {**data, "id": row_id}
                session.add(ObservationRow(**row_data))
            await session.commit()
            return row_id

    async def latest_observation_per_primitive(
        self, attacker_uuid: str,
    ) -> dict[str, dict[str, Any]]:
        """Return the most recent observation per primitive for one
        attacker.

        Output shape::

            {
              "motor.input_modality":   {"value": "pasted",
                                         "confidence": 0.91,
                                         "ts": 1714521660.456,
                                         "source": "..."},
              "cognitive.feedback_loop_engagement": {...},
              ...
            }

        Empty dict when the attacker has zero observations.
        Implementation uses a per-primitive MAX(ts) subquery; portable
        across SQLite + MySQL (no ``DISTINCT ON``).
        """
        async with self._session() as session:
            # Subquery: per-primitive max(ts) for this attacker.
            max_ts_subq = (
                select(
                    col(ObservationRow.primitive).label("primitive"),
                    func.max(col(ObservationRow.ts)).label("max_ts"),
                )
                .where(ObservationRow.attacker_uuid == attacker_uuid)
                .group_by(col(ObservationRow.primitive))
                .subquery()
            )
            stmt = (
                select(ObservationRow)
                .join(
                    max_ts_subq,
                    (ObservationRow.primitive == max_ts_subq.c.primitive)
                    & (ObservationRow.ts == max_ts_subq.c.max_ts),
                )
                .where(ObservationRow.attacker_uuid == attacker_uuid)
                .order_by(ObservationRow.primitive)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return {
                row.primitive: {
                    "value": row.value,
                    "confidence": row.confidence,
                    "ts": row.ts,
                    "source": row.source,
                }
                for row in rows
            }

    async def observations_time_series(
        self, attacker_uuid: str, primitive: str,
    ) -> list[dict[str, Any]]:
        """Return every observation of ``primitive`` for ``attacker_uuid``,
        ordered by ``ts`` ASC.

        Empty list when no rows match.
        """
        async with self._session() as session:
            stmt = (
                select(ObservationRow)
                .where(
                    ObservationRow.attacker_uuid == attacker_uuid,
                    ObservationRow.primitive == primitive,
                )
                .order_by(ObservationRow.ts)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "ts": row.ts,
                    "value": row.value,
                    "confidence": row.confidence,
                }
                for row in rows
            ]

    async def get_observation_by_id(
        self, row_id: str,
    ) -> Optional[dict[str, Any]]:
        """Single ``ObservationRow`` lookup by ``id``. Used by tests
        and a future "fetch one event" surface; not exposed on the
        public API today."""
        async with self._session() as session:
            stmt = select(ObservationRow).where(ObservationRow.id == row_id)
            row = (await session.execute(stmt)).scalar_one_or_none()
            if not row:
                return None
            return row.model_dump(mode="json")

    async def observations_for_identity_primitive(
        self, identity_uuid: str, primitive: str,
    ) -> list[dict[str, Any]]:
        """Union of every observation of *primitive* across the
        attackers rolling up to *identity_uuid*, ordered ``ts`` ASC.

        v0 with 1:1 stub identities returns the same set as
        ``observations_time_series(attacker_uuid, primitive)``.
        v1's clusterer makes the union load-bearing — multiple
        attackers point at the same identity_id and this query is
        what gives the merger a cross-attacker view.
        """
        async with self._session() as session:
            stmt = (
                select(ObservationRow)
                .join(Attacker, ObservationRow.attacker_uuid == Attacker.uuid)
                .where(
                    Attacker.identity_id == identity_uuid,
                    ObservationRow.primitive == primitive,
                )
                .order_by(ObservationRow.ts)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {"ts": row.ts, "value": row.value, "confidence": row.confidence}
                for row in rows
            ]

    async def has_observations_for_evidence(
        self, evidence_ref: str,
    ) -> bool:
        """True iff any observation row carries this ``evidence_ref``.

        Worker uses this as the "have we already profiled this session?"
        check before kicking the extractor — equivalent to "is this
        ``(decky, service, sid)`` already in the table?"
        """
        async with self._session() as session:
            stmt = (
                select(col(ObservationRow.id))
                .where(ObservationRow.evidence_ref == evidence_ref)
                .limit(1)
            )
            return (await session.execute(stmt)).scalar_one_or_none() is not None

    async def list_observations_by_attacker(
        self, attacker_uuid: str,
    ) -> list[dict[str, Any]]:
        """All observations for *attacker_uuid*, ordered by ``window_end_ts``
        ASC, shaped as BEHAVE envelope dicts.
        """
        async with self._session() as session:
            stmt = (
                select(ObservationRow)
                .where(ObservationRow.attacker_uuid == attacker_uuid)
                .order_by(ObservationRow.window_end_ts)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_to_envelope(row) for row in rows]

    async def get_all_observations_for_export(
        self,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return ``{attacker_uuid: [envelope, ...]}`` for all attackers."""
        async with self._session() as session:
            stmt = (
                select(ObservationRow)
                .order_by(ObservationRow.attacker_uuid, ObservationRow.window_end_ts)
            )
            rows = (await session.execute(stmt)).scalars().all()
            result: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                result.setdefault(row.attacker_uuid, []).append(_to_envelope(row))
            return result

    # Order desc(ts) reserved as the most-recent-first listing if a
    # paginated UI surface lands later. Not exposed today; named here
    # so a future grep finds the canonical desc-ts pattern.
    _LATEST_FIRST = staticmethod(desc)
