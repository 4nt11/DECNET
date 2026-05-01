"""Log ingestion, query, and the stats summary endpoint.

``get_log_histogram`` is the per-dialect override point; the abstract
default raises NotImplementedError.  ``get_stats_summary`` joins log
counts, topology-decky counts, and the on-disk fleet state into a
single dashboard payload.
"""
from __future__ import annotations

import asyncio
import re
import shlex
from datetime import datetime
from typing import Any, List, Optional

import orjson
from sqlalchemy import asc, desc, func, or_, select, text
from sqlmodel import col
from sqlmodel.sql.expression import SelectOfScalar

from decnet.config import load_state
from decnet.web.db.models import Log, TopologyDecky


from decnet.web.db.sqlmodel_repo._helpers import _MixinBase

class LogsMixin(_MixinBase):
    """Mixin: composed onto ``SQLModelRepository``."""

    @staticmethod
    def _normalize_log_row(log_data: dict[str, Any]) -> dict[str, Any]:
        data = log_data.copy()
        if "fields" in data and isinstance(data["fields"], dict):
            data["fields"] = orjson.dumps(data["fields"]).decode()
        if "timestamp" in data and isinstance(data["timestamp"], str):
            try:
                data["timestamp"] = datetime.fromisoformat(
                    data["timestamp"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        return data

    async def add_log(self, log_data: dict[str, Any]) -> None:
        data = self._normalize_log_row(log_data)
        async with self._session() as session:
            session.add(Log(**data))
            await session.commit()

    async def add_logs(self, log_entries: list[dict[str, Any]]) -> None:
        """Bulk insert — one session, one commit for the whole batch."""
        if not log_entries:
            return
        _rows = [Log(**self._normalize_log_row(e)) for e in log_entries]
        async with self._session() as session:
            session.add_all(_rows)
            await session.commit()

    def _apply_filters(
        self,
        statement: SelectOfScalar,
        search: Optional[str],
        start_time: Optional[str],
        end_time: Optional[str],
    ) -> SelectOfScalar:
        if start_time:
            statement = statement.where(col(Log.timestamp) >= start_time)
        if end_time:
            statement = statement.where(col(Log.timestamp) <= end_time)

        if search:
            try:
                tokens = shlex.split(search)
            except ValueError:
                tokens = search.split()

            core_fields = {
                "decky": Log.decky,
                "service": Log.service,
                "event": Log.event_type,
                "attacker": Log.attacker_ip,
                "attacker-ip": Log.attacker_ip,
                "attacker_ip": Log.attacker_ip,
            }

            for token in tokens:
                if ":" in token:
                    key, val = token.split(":", 1)
                    if key in core_fields:
                        statement = statement.where(core_fields[key] == val)
                    else:
                        key_safe = re.sub(r"[^a-zA-Z0-9_]", "", key)
                        if key_safe:
                            statement = statement.where(
                                self._json_field_equals(key_safe)
                            ).params(val=val)
                else:
                    lk = f"%{token}%"
                    statement = statement.where(
                        or_(
                            col(Log.raw_line).like(lk),
                            col(Log.decky).like(lk),
                            col(Log.service).like(lk),
                            col(Log.attacker_ip).like(lk),
                        )
                    )
        return statement

    def _json_field_equals(self, key: str):
        """Return a text() predicate that matches rows where fields->key == :val.

        Both SQLite and MySQL expose a ``JSON_EXTRACT`` function; MySQL also
        exposes the same function under ``json_extract`` (case-insensitive).
        The ``:val`` parameter is bound separately and must be supplied with
        ``.params(val=...)`` by the caller, which keeps us safe from injection.
        """
        return text(f"JSON_EXTRACT(fields, '$.{key}') = :val")

    async def get_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[dict]:
        statement = (
            select(Log)
            .order_by(desc(Log.timestamp))
            .offset(offset)
            .limit(limit)
        )
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self._session() as session:
            results = await session.execute(statement)
            return [log.model_dump(mode="json") for log in results.scalars().all()]

    async def get_max_log_id(self) -> int:
        async with self._session() as session:
            result = await session.execute(select(func.max(Log.id)))
            val = result.scalar()
            return val if val is not None else 0

    async def get_logs_after_id(
        self,
        last_id: int,
        limit: int = 50,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[dict]:
        statement = (
            select(Log).where(col(Log.id) > last_id).order_by(asc(Log.id)).limit(limit)
        )
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self._session() as session:
            results = await session.execute(statement)
            return [log.model_dump(mode="json") for log in results.scalars().all()]

    async def get_total_logs(
        self,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> int:
        statement = select(func.count()).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def get_log_histogram(
        self,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interval_minutes: int = 15,
    ) -> List[dict]:
        """Dialect-specific — override per backend."""
        raise NotImplementedError

    async def get_stats_summary(self) -> dict[str, Any]:
        async with self._session() as session:
            total_logs = (
                await session.execute(select(func.count()).select_from(Log))
            ).scalar() or 0
            unique_attackers = (
                await session.execute(
                    select(func.count(func.distinct(Log.attacker_ip)))
                )
            ).scalar() or 0
            topo_total = (
                await session.execute(select(func.count()).select_from(TopologyDecky))
            ).scalar() or 0
            topo_running = (
                await session.execute(
                    select(func.count())
                    .select_from(TopologyDecky)
                    .where(TopologyDecky.state == "running")
                )
            ).scalar() or 0

        _state = await asyncio.to_thread(load_state)
        fleet_deckies = len(_state[0].deckies) if _state else 0

        return {
            "total_logs": total_logs,
            "unique_attackers": unique_attackers,
            # Fleet state file doesn't track per-decky runtime; treat all
            # fleet rows as active and add MazeNET running rows on top.
            "active_deckies": fleet_deckies + topo_running,
            "deployed_deckies": fleet_deckies + topo_total,
        }
