"""Attacker-intel domain methods.

Owns reads/writes for ``AttackerIntel`` rows: per-attacker enrichment
data sourced from external providers (GreyNoise, AbuseIPDB, Feodo,
ThreatFox).  Joined against ``Attacker`` for the unenriched-backlog
worker query.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import desc, or_, select
from sqlmodel import col

from decnet.web.db.models import Attacker, AttackerIntel


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class AttackerIntelMixin(_MixinBase):
    """Mixin: methods composed onto ``SQLModelRepository``.

    Expects ``self._session()`` from the base.
    """

    async def upsert_attacker_intel(self, data: dict[str, Any]) -> str:
        attacker_uuid_value = data["attacker_uuid"]
        async with self._session() as session:
            result = await session.execute(
                select(AttackerIntel).where(
                    AttackerIntel.attacker_uuid == attacker_uuid_value,
                )
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
                row_uuid = existing.uuid
            else:
                row_uuid = _uuid.uuid4().hex
                session.add(AttackerIntel(uuid=row_uuid, **data))
            await session.commit()
            return row_uuid

    async def get_attacker_intel_by_uuid(
        self,
        uuid: str,
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(AttackerIntel).where(AttackerIntel.attacker_uuid == uuid)
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            d = row.model_dump(mode="json")
            # Two passes: ``*_raw`` columns hold provider response blobs
            # (objects); the per-provider taxonomy columns hold JSON
            # arrays the IntelLifter consumes as native lists.
            for key in (
                "greynoise_raw",
                "abuseipdb_raw",
                "feodo_raw",
                "threatfox_raw",
                "greynoise_tags",
                "abuseipdb_categories",
                "threatfox_threat_types",
                "threatfox_ioc_types",
                "threatfox_malware_families",
            ):
                raw = d.get(key)
                if isinstance(raw, str):
                    try:
                        d[key] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        pass
            return d

    async def get_unenriched_attackers(
        self, limit: int = 100,
    ) -> list[dict[str, Any]]:
        """``{"uuid", "ip"}`` pairs with no intel row OR a stale (expired) one.

        Stale = ``expires_at < now``. Ordered by ``attackers.last_seen`` desc
        so the worker prioritises recent activity on backfill. Both columns
        are projected so the worker can write keyed on UUID and dispatch
        provider calls keyed on IP without a second round-trip.
        """
        now = datetime.now(timezone.utc)
        async with self._session() as session:
            stmt = (
                select(col(Attacker.uuid), col(Attacker.ip))
                .outerjoin(
                    AttackerIntel, AttackerIntel.attacker_uuid == Attacker.uuid,
                )
                .where(
                    or_(
                        col(AttackerIntel.uuid).is_(None),
                        AttackerIntel.expires_at < now,
                    )
                )
                .order_by(desc(Attacker.last_seen))
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [
                {"uuid": uuid_, "ip": ip}
                for uuid_, ip in result.all()
            ]
