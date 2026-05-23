# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-attacker behavior signals (TCP fingerprint, timing stats, phase
sequence, tool guesses, KEX order, SSH client banners)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlmodel import col

from decnet.web.db.models import Attacker, AttackerBehavior


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class AttackerBehaviorMixin(_MixinBase):
    async def upsert_attacker_behavior(
        self,
        attacker_uuid: str,
        data: dict[str, Any],
    ) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(AttackerBehavior).where(
                    AttackerBehavior.attacker_uuid == attacker_uuid
                )
            )
            existing = result.scalar_one_or_none()
            payload = {**data, "updated_at": datetime.now(timezone.utc)}
            if existing:
                for k, v in payload.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                session.add(AttackerBehavior(attacker_uuid=attacker_uuid, **payload))
            await session.commit()

    async def get_attacker_behavior(
        self,
        attacker_uuid: str,
    ) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(AttackerBehavior).where(
                    AttackerBehavior.attacker_uuid == attacker_uuid
                )
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            return self._deserialize_behavior(row.model_dump(mode="json"))

    async def get_behaviors_for_ips(
        self,
        ips: set[str],
    ) -> dict[str, dict[str, Any]]:
        if not ips:
            return {}
        async with self._session() as session:
            result = await session.execute(
                select(col(Attacker.ip), AttackerBehavior)
                .join(AttackerBehavior, Attacker.uuid == AttackerBehavior.attacker_uuid)
                .where(col(Attacker.ip).in_(ips))
            )
            out: dict[str, dict[str, Any]] = {}
            for ip, row in result.all():
                out[ip] = self._deserialize_behavior(row.model_dump(mode="json"))
            return out

    @staticmethod
    def _deserialize_behavior(d: dict[str, Any]) -> dict[str, Any]:
        for key in ("tcp_fingerprint", "timing_stats", "phase_sequence"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Deserialize tool_guesses JSON array; normalise None → [].
        raw = d.get("tool_guesses")
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                d["tool_guesses"] = parsed if isinstance(parsed, list) else [parsed]
            except (json.JSONDecodeError, TypeError):
                d["tool_guesses"] = []
        elif raw is None:
            d["tool_guesses"] = []
        # Same list-or-None pattern for kex_order_raw.
        raw_kex = d.get("kex_order_raw")
        if isinstance(raw_kex, str):
            try:
                parsed_kex = json.loads(raw_kex)
                d["kex_order_raw"] = parsed_kex if isinstance(parsed_kex, list) else [parsed_kex]
            except (json.JSONDecodeError, TypeError):
                d["kex_order_raw"] = []
        elif raw_kex is None:
            d["kex_order_raw"] = []
        # Same list-or-None pattern for ssh_client_banners.
        raw_banners = d.get("ssh_client_banners")
        if isinstance(raw_banners, str):
            try:
                parsed_banners = json.loads(raw_banners)
                d["ssh_client_banners"] = parsed_banners if isinstance(parsed_banners, list) else [parsed_banners]
            except (json.JSONDecodeError, TypeError):
                d["ssh_client_banners"] = []
        elif raw_banners is None:
            d["ssh_client_banners"] = []
        return d
