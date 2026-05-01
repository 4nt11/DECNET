"""Decky-shard CRUD (per-host shard registrations)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import orjson
from sqlalchemy import asc, select, text

from decnet.web.db.models import DeckyShard


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class DeckiesMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    async def upsert_decky_shard(self, data: dict[str, Any]) -> None:
        payload = {**data, "updated_at": datetime.now(timezone.utc)}
        if isinstance(payload.get("services"), list):
            payload["services"] = orjson.dumps(payload["services"]).decode()
        async with self._session() as session:
            result = await session.execute(
                select(DeckyShard).where(DeckyShard.decky_name == payload["decky_name"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in payload.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                session.add(DeckyShard(**payload))
            await session.commit()

    async def list_decky_shards(
        self, host_uuid: Optional[str] = None
    ) -> list[dict[str, Any]]:
        statement = select(DeckyShard).order_by(asc(DeckyShard.decky_name))
        if host_uuid:
            statement = statement.where(DeckyShard.host_uuid == host_uuid)
        async with self._session() as session:
            result = await session.execute(statement)
            out: list[dict[str, Any]] = []
            for r in result.scalars().all():
                d = r.model_dump(mode="json")
                raw = d.get("services")
                if isinstance(raw, str):
                    try:
                        d["services"] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        d["services"] = []
                # Flatten the stored DeckyConfig snapshot into the row so
                # routers can hand it to DeckyShardView without re-parsing.
                # Rows predating the migration have decky_config=NULL and
                # fall through with the default (None/{}) view values.
                cfg_raw = d.get("decky_config")
                if isinstance(cfg_raw, str):
                    try:
                        cfg = json.loads(cfg_raw)
                    except (json.JSONDecodeError, TypeError):
                        cfg = {}
                    if isinstance(cfg, dict):
                        for k in ("hostname", "distro", "archetype",
                                  "service_config", "mutate_interval",
                                  "last_mutated"):
                            if k in cfg and d.get(k) is None:
                                d[k] = cfg[k]
                        # Keep decky_ip authoritative from the column (newer
                        # heartbeats overwrite it) but fall back to the
                        # snapshot if the column is still NULL.
                        if not d.get("decky_ip") and cfg.get("ip"):
                            d["decky_ip"] = cfg["ip"]
                out.append(d)
            return out

    async def delete_decky_shards_for_host(self, host_uuid: str) -> int:
        async with self._session() as session:
            result = await session.execute(
                text("DELETE FROM decky_shards WHERE host_uuid = :u"),
                {"u": host_uuid},
            )
            await session.commit()
            return result.rowcount or 0

    async def delete_decky_shard(self, decky_name: str) -> bool:
        async with self._session() as session:
            result = await session.execute(
                text("DELETE FROM decky_shards WHERE decky_name = :n"),
                {"n": decky_name},
            )
            await session.commit()
            return bool(result.rowcount)
