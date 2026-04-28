"""Bounty CRUD + the global purge helper that wipes logs/bounties/credentials/attackers together."""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, List, Optional

import orjson
from sqlalchemy import asc, desc, func, or_, select, text
from sqlmodel.sql.expression import SelectOfScalar

from decnet.web.db.models import Bounty


class BountiesMixin:
    """Mixin: composed onto ``SQLModelRepository``."""

    async def purge_logs_and_bounties(self) -> dict[str, int]:
        async with self._session() as session:
            logs_deleted = (await session.execute(text("DELETE FROM logs"))).rowcount
            bounties_deleted = (await session.execute(text("DELETE FROM bounty"))).rowcount
            credentials_deleted = (
                await session.execute(text("DELETE FROM credentials"))
            ).rowcount
            # attacker_behavior has FK → attackers.uuid; delete children first.
            await session.execute(text("DELETE FROM attacker_behavior"))
            attackers_deleted = (await session.execute(text("DELETE FROM attackers"))).rowcount
            await session.commit()
        return {
            "logs": logs_deleted,
            "bounties": bounties_deleted,
            "credentials": credentials_deleted,
            "attackers": attackers_deleted,
        }

    async def add_bounty(self, bounty_data: dict[str, Any]) -> None:
        data = bounty_data.copy()
        if "payload" in data and isinstance(data["payload"], dict):
            data["payload"] = orjson.dumps(data["payload"]).decode()

        async with self._session() as session:
            dup = await session.execute(
                select(Bounty.id).where(
                    Bounty.bounty_type == data.get("bounty_type"),
                    Bounty.attacker_ip == data.get("attacker_ip"),
                    Bounty.payload == data.get("payload"),
                ).limit(1)
            )
            if dup.first() is not None:
                return
            session.add(Bounty(**data))
            await session.commit()

    def _apply_bounty_filters(
        self,
        statement: SelectOfScalar,
        bounty_type: Optional[str],
        search: Optional[str],
    ) -> SelectOfScalar:
        if bounty_type:
            statement = statement.where(Bounty.bounty_type == bounty_type)
        if search:
            lk = f"%{search}%"
            statement = statement.where(
                or_(
                    Bounty.decky.like(lk),
                    Bounty.service.like(lk),
                    Bounty.attacker_ip.like(lk),
                    Bounty.payload.like(lk),
                )
            )
        return statement

    async def get_bounties(
        self,
        limit: int = 50,
        offset: int = 0,
        bounty_type: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[dict]:
        statement = (
            select(Bounty)
            .order_by(desc(Bounty.timestamp))
            .offset(offset)
            .limit(limit)
        )
        statement = self._apply_bounty_filters(statement, bounty_type, search)

        async with self._session() as session:
            results = await session.execute(statement)
            final = []
            for item in results.scalars().all():
                d = item.model_dump(mode="json")
                try:
                    d["payload"] = json.loads(d["payload"])
                except (json.JSONDecodeError, TypeError):
                    pass
                final.append(d)
            return final

    async def get_total_bounties(
        self, bounty_type: Optional[str] = None, search: Optional[str] = None
    ) -> int:
        statement = select(func.count()).select_from(Bounty)
        statement = self._apply_bounty_filters(statement, bounty_type, search)

        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def get_all_bounties_by_ip(self) -> dict[str, List[dict[str, Any]]]:
        async with self._session() as session:
            result = await session.execute(
                select(Bounty).order_by(asc(Bounty.timestamp))
            )
            grouped: dict[str, List[dict[str, Any]]] = defaultdict(list)
            for item in result.scalars().all():
                d = item.model_dump(mode="json")
                try:
                    d["payload"] = json.loads(d["payload"])
                except (json.JSONDecodeError, TypeError):
                    pass
                grouped[item.attacker_ip].append(d)
            return dict(grouped)

    async def get_bounties_for_ips(self, ips: set[str]) -> dict[str, List[dict[str, Any]]]:
        async with self._session() as session:
            result = await session.execute(
                select(Bounty).where(Bounty.attacker_ip.in_(ips)).order_by(asc(Bounty.timestamp))
            )
            grouped: dict[str, List[dict[str, Any]]] = defaultdict(list)
            for item in result.scalars().all():
                d = item.model_dump(mode="json")
                try:
                    d["payload"] = json.loads(d["payload"])
                except (json.JSONDecodeError, TypeError):
                    pass
                grouped[item.attacker_ip].append(d)
            return dict(grouped)
