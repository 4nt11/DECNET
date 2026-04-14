import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Optional, List

from sqlalchemy import func, select, desc, asc, text, or_, update, literal_column
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel.sql.expression import SelectOfScalar

from decnet.config import load_state, _ROOT
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import get_password_hash
from decnet.web.db.repository import BaseRepository
from decnet.web.db.models import User, Log, Bounty, State, Attacker
from decnet.web.db.sqlite.database import get_async_engine


class SQLiteRepository(BaseRepository):
    """SQLite implementation using SQLModel and SQLAlchemy Async."""

    def __init__(self, db_path: str = str(_ROOT / "decnet.db")) -> None:
        self.db_path = db_path
        self.engine = get_async_engine(db_path)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def initialize(self) -> None:
        """Async warm-up / verification. Creates tables if they don't exist."""
        from sqlmodel import SQLModel
        await self._migrate_attackers_table()
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        async with self.session_factory() as session:
            # Check if admin exists
            result = await session.execute(
                select(User).where(User.username == DECNET_ADMIN_USER)
            )
            if not result.scalar_one_or_none():
                session.add(User(
                    uuid=str(uuid.uuid4()),
                    username=DECNET_ADMIN_USER,
                    password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                    role="admin",
                    must_change_password=True,
                ))
                await session.commit()

    async def _migrate_attackers_table(self) -> None:
        """Drop the old attackers table if it lacks the uuid column (pre-UUID schema)."""
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text("PRAGMA table_info(attackers)"))).fetchall()
            if rows and not any(r[1] == "uuid" for r in rows):
                await conn.execute(text("DROP TABLE attackers"))

    async def reinitialize(self) -> None:
        """Initialize the database schema asynchronously (useful for tests)."""
        from sqlmodel import SQLModel
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        async with self.session_factory() as session:
            result = await session.execute(
                select(User).where(User.username == DECNET_ADMIN_USER)
            )
            if not result.scalar_one_or_none():
                session.add(User(
                    uuid=str(uuid.uuid4()),
                    username=DECNET_ADMIN_USER,
                    password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                    role="admin",
                    must_change_password=True,
                ))
                await session.commit()

    # ------------------------------------------------------------------ logs

    async def add_log(self, log_data: dict[str, Any]) -> None:
        data = log_data.copy()
        if "fields" in data and isinstance(data["fields"], dict):
            data["fields"] = json.dumps(data["fields"])
        if "timestamp" in data and isinstance(data["timestamp"], str):
            try:
                data["timestamp"] = datetime.fromisoformat(
                    data["timestamp"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        async with self.session_factory() as session:
            session.add(Log(**data))
            await session.commit()

    def _apply_filters(
        self,
        statement: SelectOfScalar,
        search: Optional[str],
        start_time: Optional[str],
        end_time: Optional[str],
    ) -> SelectOfScalar:
        import re
        import shlex

        if start_time:
            statement = statement.where(Log.timestamp >= start_time)
        if end_time:
            statement = statement.where(Log.timestamp <= end_time)

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
                                text(f"json_extract(fields, '$.{key_safe}') = :val")
                            ).params(val=val)
                else:
                    lk = f"%{token}%"
                    statement = statement.where(
                        or_(
                            Log.raw_line.like(lk),
                            Log.decky.like(lk),
                            Log.service.like(lk),
                            Log.attacker_ip.like(lk),
                        )
                    )
        return statement

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

        async with self.session_factory() as session:
            results = await session.execute(statement)
            return [log.model_dump(mode='json') for log in results.scalars().all()]

    async def get_max_log_id(self) -> int:
        async with self.session_factory() as session:
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
            select(Log).where(Log.id > last_id).order_by(asc(Log.id)).limit(limit)
        )
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self.session_factory() as session:
            results = await session.execute(statement)
            return [log.model_dump(mode='json') for log in results.scalars().all()]

    async def get_total_logs(
        self,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> int:
        statement = select(func.count()).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self.session_factory() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def get_log_histogram(
        self,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interval_minutes: int = 15,
    ) -> List[dict]:
        bucket_seconds = max(interval_minutes, 1) * 60
        bucket_expr = literal_column(
            f"datetime((strftime('%s', timestamp) / {bucket_seconds}) * {bucket_seconds}, 'unixepoch')"
        ).label("bucket_time")

        statement = select(bucket_expr, func.count().label("count")).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)
        statement = statement.group_by(literal_column("bucket_time")).order_by(
            literal_column("bucket_time")
        )

        async with self.session_factory() as session:
            results = await session.execute(statement)
            return [{"time": r[0], "count": r[1]} for r in results.all()]

    async def get_stats_summary(self) -> dict[str, Any]:
        async with self.session_factory() as session:
            total_logs = (
                await session.execute(select(func.count()).select_from(Log))
            ).scalar() or 0
            unique_attackers = (
                await session.execute(
                    select(func.count(func.distinct(Log.attacker_ip)))
                )
            ).scalar() or 0

        _state = await asyncio.to_thread(load_state)
        deployed_deckies = len(_state[0].deckies) if _state else 0

        return {
            "total_logs": total_logs,
            "unique_attackers": unique_attackers,
            "active_deckies": deployed_deckies,
            "deployed_deckies": deployed_deckies,
        }

    async def get_deckies(self) -> List[dict]:
        _state = await asyncio.to_thread(load_state)
        return [_d.model_dump() for _d in _state[0].deckies] if _state else []

    # ------------------------------------------------------------------ users

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(User).where(User.username == username)
            )
            user = result.scalar_one_or_none()
            return user.model_dump() if user else None

    async def get_user_by_uuid(self, uuid: str) -> Optional[dict]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(User).where(User.uuid == uuid)
            )
            user = result.scalar_one_or_none()
            return user.model_dump() if user else None

    async def create_user(self, user_data: dict[str, Any]) -> None:
        async with self.session_factory() as session:
            session.add(User(**user_data))
            await session.commit()

    async def update_user_password(
        self, uuid: str, password_hash: str, must_change_password: bool = False
    ) -> None:
        async with self.session_factory() as session:
            await session.execute(
                update(User)
                .where(User.uuid == uuid)
                .values(
                    password_hash=password_hash,
                    must_change_password=must_change_password,
                )
            )
            await session.commit()

    # ---------------------------------------------------------------- bounties

    async def add_bounty(self, bounty_data: dict[str, Any]) -> None:
        data = bounty_data.copy()
        if "payload" in data and isinstance(data["payload"], dict):
            data["payload"] = json.dumps(data["payload"])

        async with self.session_factory() as session:
            session.add(Bounty(**data))
            await session.commit()

    def _apply_bounty_filters(
        self,
        statement: SelectOfScalar,
        bounty_type: Optional[str],
        search: Optional[str]
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

        async with self.session_factory() as session:
            results = await session.execute(statement)
            final = []
            for item in results.scalars().all():
                d = item.model_dump(mode='json')
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

        async with self.session_factory() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def get_state(self, key: str) -> Optional[dict[str, Any]]:
        async with self.session_factory() as session:
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()
            if state:
                return json.loads(state.value)
            return None

    async def set_state(self, key: str, value: Any) -> None:  # noqa: ANN401
        async with self.session_factory() as session:
            # Check if exists
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()

            value_json = json.dumps(value)
            if state:
                state.value = value_json
                session.add(state)
            else:
                new_state = State(key=key, value=value_json)
                session.add(new_state)

            await session.commit()

    # --------------------------------------------------------------- attackers

    async def get_all_logs_raw(self) -> List[dict[str, Any]]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(
                    Log.id,
                    Log.raw_line,
                    Log.attacker_ip,
                    Log.service,
                    Log.event_type,
                    Log.decky,
                    Log.timestamp,
                    Log.fields,
                )
            )
            return [
                {
                    "id": r.id,
                    "raw_line": r.raw_line,
                    "attacker_ip": r.attacker_ip,
                    "service": r.service,
                    "event_type": r.event_type,
                    "decky": r.decky,
                    "timestamp": r.timestamp,
                    "fields": r.fields,
                }
                for r in result.all()
            ]

    async def get_all_bounties_by_ip(self) -> dict[str, List[dict[str, Any]]]:
        from collections import defaultdict
        async with self.session_factory() as session:
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
        from collections import defaultdict
        async with self.session_factory() as session:
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

    async def upsert_attacker(self, data: dict[str, Any]) -> None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.ip == data["ip"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
            else:
                data["uuid"] = str(uuid.uuid4())
                session.add(Attacker(**data))
            await session.commit()

    @staticmethod
    def _deserialize_attacker(d: dict[str, Any]) -> dict[str, Any]:
        """Parse JSON-encoded list fields in an attacker dict."""
        for key in ("services", "deckies", "fingerprints", "commands"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    async def get_attacker_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.uuid == uuid)
            )
            attacker = result.scalar_one_or_none()
            if not attacker:
                return None
            return self._deserialize_attacker(attacker.model_dump(mode="json"))

    async def get_attackers(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        sort_by: str = "recent",
    ) -> List[dict[str, Any]]:
        order = {
            "active": desc(Attacker.event_count),
            "traversals": desc(Attacker.is_traversal),
        }.get(sort_by, desc(Attacker.last_seen))

        statement = select(Attacker).order_by(order).offset(offset).limit(limit)
        if search:
            statement = statement.where(Attacker.ip.like(f"%{search}%"))

        async with self.session_factory() as session:
            result = await session.execute(statement)
            return [
                self._deserialize_attacker(a.model_dump(mode="json"))
                for a in result.scalars().all()
            ]

    async def get_total_attackers(self, search: Optional[str] = None) -> int:
        statement = select(func.count()).select_from(Attacker)
        if search:
            statement = statement.where(Attacker.ip.like(f"%{search}%"))

        async with self.session_factory() as session:
            result = await session.execute(statement)
            return result.scalar() or 0
