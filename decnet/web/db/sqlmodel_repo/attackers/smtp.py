# SPDX-License-Identifier: AGPL-3.0-or-later
"""SMTP victim-domain tracking (per-attacker counters and
cross-attacker aggregate)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, func, select

from decnet.web.db.models import SmtpTarget


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class SmtpTargetsMixin(_MixinBase):
    async def increment_smtp_target(self, attacker_uuid: str, domain: str) -> None:
        """Upsert an (attacker_uuid, domain) pair and bump count + last_seen.

        Read-then-write under a single session — the UNIQUE constraint on
        (attacker_uuid, domain) guards against duplicate rows if the race
        ever materialises; we accept the ~1ms extra round-trip in exchange
        for a single dialect-portable implementation.
        """
        async with self._session() as session:
            result = await session.execute(
                select(SmtpTarget)
                .where(SmtpTarget.attacker_uuid == attacker_uuid)
                .where(SmtpTarget.domain == domain)
            )
            existing = result.scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if existing:
                existing.count += 1
                existing.last_seen = now
                session.add(existing)
            else:
                session.add(SmtpTarget(
                    attacker_uuid=attacker_uuid,
                    domain=domain,
                    first_seen=now,
                    last_seen=now,
                    count=1,
                ))
            await session.commit()

    async def list_smtp_targets(self, attacker_uuid: str) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(SmtpTarget)
                .where(SmtpTarget.attacker_uuid == attacker_uuid)
                .order_by(desc(SmtpTarget.last_seen))
            )
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def smtp_target_seen(self, domain: str) -> dict[str, Any]:
        """Aggregate rows for this domain across every attacker in the DB."""
        async with self._session() as session:
            result = await session.execute(
                select(
                    func.coalesce(func.sum(SmtpTarget.count), 0),
                    func.min(SmtpTarget.first_seen),
                    func.max(SmtpTarget.last_seen),
                ).where(SmtpTarget.domain == domain)
            )
            total, first_seen, last_seen = result.one()
            return {
                "seen": int(total) > 0,
                "count": int(total),
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
