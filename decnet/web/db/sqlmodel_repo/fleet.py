"""Fleet decky CRUD + cross-source running-decky aggregator."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import orjson
from sqlalchemy import asc, select, text, update

from decnet.web.db.models import DeckyShard, FleetDecky, LOCAL_HOST_SENTINEL
from decnet.web.db.sqlmodel_repo._helpers import _deserialize_json_fields


class FleetMixin:
    """Mixin: composed onto ``SQLModelRepository``.

    ``list_running_deckies`` aggregates topology + fleet + swarm-shard
    sources and stays here because the fleet entry is the canonical
    shape; ``list_running_topology_deckies`` / ``list_running_fleet_deckies``
    on ``self`` resolve through the composed class.
    """

    async def upsert_fleet_decky(self, data: dict[str, Any]) -> None:
        payload: dict[str, Any] = {
            **data,
            "updated_at": datetime.now(timezone.utc),
        }
        payload.setdefault("host_uuid", LOCAL_HOST_SENTINEL)
        if payload.get("host_uuid") is None:
            payload["host_uuid"] = LOCAL_HOST_SENTINEL
        if isinstance(payload.get("services"), list):
            payload["services"] = orjson.dumps(payload["services"]).decode()
        if isinstance(payload.get("decky_config"), dict):
            payload["decky_config"] = orjson.dumps(payload["decky_config"]).decode()
        async with self._session() as session:
            result = await session.execute(
                select(FleetDecky).where(
                    FleetDecky.host_uuid == payload["host_uuid"],
                    FleetDecky.name == payload["name"],
                )
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in payload.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                session.add(FleetDecky(**payload))
            await session.commit()

    async def delete_fleet_decky(self, *, host_uuid: str, name: str) -> None:
        async with self._session() as session:
            await session.execute(
                text(
                    "DELETE FROM fleet_deckies "
                    "WHERE host_uuid = :h AND name = :n"
                ),
                {"h": host_uuid, "n": name},
            )
            await session.commit()

    async def list_fleet_deckies(
        self, *, host_uuid: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        stmt = select(FleetDecky).order_by(asc(FleetDecky.name))
        if host_uuid:
            stmt = stmt.where(FleetDecky.host_uuid == host_uuid)
        async with self._session() as session:
            result = await session.execute(stmt)
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("services", "decky_config")
                )
                for r in result.scalars().all()
            ]

    async def list_running_fleet_deckies(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(
                select(FleetDecky).where(FleetDecky.state == "running")
            )
            return [
                _deserialize_json_fields(
                    r.model_dump(mode="json"), ("services", "decky_config")
                )
                for r in result.scalars().all()
            ]

    async def update_fleet_decky_state(
        self, *, host_uuid: str, name: str, state: str,
        last_error: Optional[str] = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        values: dict[str, Any] = {
            "state": state,
            "updated_at": now,
            "last_seen": now,
        }
        if last_error is not None:
            values["last_error"] = last_error
        async with self._session() as session:
            await session.execute(
                update(FleetDecky)
                .where(
                    FleetDecky.host_uuid == host_uuid,
                    FleetDecky.name == name,
                )
                .values(**values)
            )
            await session.commit()

    async def list_running_deckies(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        # MazeNET — already shaped {uuid, name, ip, services}.  We carry
        # topology_id through so consumers (emailgen scheduler) can walk
        # back to the parent topology row without a second round-trip;
        # fleet/shard rows never have one, hence Optional.
        for d in await self.list_running_topology_deckies():
            out.append({
                "uuid": d.get("uuid"),
                "name": d.get("name"),
                "ip": d.get("ip"),
                "services": d.get("services") or [],
                "topology_id": d.get("topology_id"),
                "source": "topology",
            })
        # Fleet — column is `decky_ip`, PK is composite (host_uuid, name)
        for d in await self.list_running_fleet_deckies():
            out.append({
                "uuid": f"{d.get('host_uuid')}:{d.get('name')}",
                "name": d.get("name"),
                "ip": d.get("decky_ip"),
                "services": d.get("services") or [],
                "source": "fleet",
            })
        # SWARM — DeckyShard rows in 'running' state on enrolled workers.
        async with self._session() as session:
            shard_rows = await session.execute(
                select(DeckyShard).where(DeckyShard.state == "running")
            )
            for s in shard_rows.scalars().all():
                d = _deserialize_json_fields(
                    s.model_dump(mode="json"), ("services", "decky_config")
                )
                out.append({
                    "uuid": f"{d.get('host_uuid')}:{d.get('decky_name')}",
                    "name": d.get("decky_name"),
                    "ip": d.get("decky_ip"),
                    "services": d.get("services") or [],
                    "source": "shard",
                })
        return out
