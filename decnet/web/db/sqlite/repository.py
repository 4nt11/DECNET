import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Optional, List

from sqlalchemy import func, select, desc, asc, text, or_, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel import col

from decnet.config import load_state, _ROOT
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import get_password_hash
from decnet.web.db.repository import BaseRepository
from decnet.web.db.models import User, Log, Bounty
from decnet.web.db.sqlite.database import get_async_engine, init_db


class SQLiteRepository(BaseRepository):
    """SQLite implementation using SQLModel and SQLAlchemy Async."""

    def __init__(self, db_path: str = str(_ROOT / "decnet.db")) -> None:
        self.db_path = db_path
        self.engine = get_async_engine(db_path)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        self._initialize_sync()

    def _initialize_sync(self) -> None:
        """Initialize the database schema synchronously."""
        init_db(self.db_path)
        
        # Ensure default admin exists via sync SQLAlchemy connection
        from sqlalchemy import select
        from decnet.web.db.sqlite.database import get_sync_engine
        engine = get_sync_engine(self.db_path)
        with engine.connect() as conn:
            # Ensure admin exists via sync SQLAlchemy connection
            from sqlalchemy import text
            result = conn.execute(text("SELECT uuid FROM users WHERE username = :u"), {"u": DECNET_ADMIN_USER})
            if not result.fetchone():
                print(f"DEBUG: Creating admin user '{DECNET_ADMIN_USER}' with password '{DECNET_ADMIN_PASSWORD}'")
                conn.execute(
                    text("INSERT INTO users (uuid, username, password_hash, role, must_change_password) "
                         "VALUES (:uuid, :u, :p, :r, :m)"),
                    {
                        "uuid": str(uuid.uuid4()),
                        "u": DECNET_ADMIN_USER,
                        "p": get_password_hash(DECNET_ADMIN_PASSWORD),
                        "r": "admin",
                        "m": 1
                    }
                )
                conn.commit()
            else:
                print(f"DEBUG: Admin user '{DECNET_ADMIN_USER}' already exists")

    async def initialize(self) -> None:
        """Async warm-up / verification."""
        async with self.session_factory() as session:
            await session.exec(text("SELECT 1"))

    def reinitialize(self) -> None:
        self._initialize_sync()

    async def add_log(self, log_data: dict[str, Any]) -> None:
        # Convert dict to model
        data = log_data.copy()
        if "fields" in data and isinstance(data["fields"], dict):
            data["fields"] = json.dumps(data["fields"])
        
        if "timestamp" in data and isinstance(data["timestamp"], str):
            try:
                data["timestamp"] = datetime.fromisoformat(data["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                pass

        log = Log(**data)
        async with self.session_factory() as session:
            session.add(log)
            await session.commit()

    def _apply_filters(self, statement, search: Optional[str], start_time: Optional[str], end_time: Optional[str]):
        import shlex
        import re

        if start_time:
            statement = statement.where(Log.timestamp >= start_time)
        if end_time:
            statement = statement.where(Log.timestamp <= end_time)

        if search:
            try:
                tokens = shlex.split(search)
            except ValueError:
                tokens = search.split(" ")

            core_fields = {
                "decky": Log.decky,
                "service": Log.service,
                "event": Log.event_type,
                "attacker": Log.attacker_ip,
                "attacker-ip": Log.attacker_ip,
                "attacker_ip": Log.attacker_ip
            }

            for token in tokens:
                if ":" in token:
                    key, val = token.split(":", 1)
                    if key in core_fields:
                        statement = statement.where(core_fields[key] == val)
                    else:
                        key_safe = re.sub(r'[^a-zA-Z0-9_]', '', key)
                        # SQLite json_extract via text()
                        statement = statement.where(text(f"json_extract(fields, '$.{key_safe}') = :val")).params(val=val)
                else:
                    lk = f"%{token}%"
                    statement = statement.where(
                        or_(
                            Log.raw_line.like(lk),
                            Log.decky.like(lk),
                            Log.service.like(lk),
                            Log.attacker_ip.like(lk)
                        )
                    )
        return statement

    async def get_logs(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[dict]:
        statement = select(Log).order_by(desc(Log.timestamp)).offset(offset).limit(limit)
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self.session_factory() as session:
            results = await session.execute(statement)
            return [log.dict() for log in results.scalars().all()]

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
        end_time: Optional[str] = None
    ) -> List[dict]:
        statement = select(Log).where(Log.id > last_id).order_by(asc(Log.id)).limit(limit)
        statement = self._apply_filters(statement, search, start_time, end_time)

        async with self.session_factory() as session:
            results = await session.execute(statement)
            return [log.dict() for log in results.scalars().all()]

    async def get_total_logs(
        self, 
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
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
        interval_minutes: int = 15
    ) -> List[dict]:
        # raw SQL for time bucketing as it is very engine specific
        _where_stmt = select(Log)
        _where_stmt = self._apply_filters(_where_stmt, search, start_time, end_time)
        
        # Extract WHERE clause from compiled statement
        # For simplicity in this migration, we'll use a semi-raw approach for the complex histogram query
        # but bind parameters from the filtered statement
        
        # SQLite specific bucket logic
        bucket_expr = f"(strftime('%s', timestamp) / {interval_minutes * 60}) * {interval_minutes * 60}"
        
        # We'll use session.execute with a text statement for the grouping but reuse the WHERE logic if possible
        # Or just build the query fully
        
        where_clause, params = self._build_where_clause_legacy(search, start_time, end_time)
        
        query = f"""
            SELECT 
                datetime({bucket_expr}, 'unixepoch') as bucket_time,
                COUNT(*) as count
            FROM logs
            {where_clause}
            GROUP BY bucket_time
            ORDER BY bucket_time ASC
        """
        
        async with self.session_factory() as session:
            results = await session.execute(text(query), params)
            return [{"time": r[0], "count": r[1]} for r in results.all()]

    def _build_where_clause_legacy(self, search, start_time, end_time):
        # Re-using the logic from the previous iteration for the raw query part
        import shlex
        import re
        where_clauses = []
        params = {}
        
        if start_time:
            where_clauses.append("timestamp >= :start_time")
            params["start_time"] = start_time
        if end_time:
            where_clauses.append("timestamp <= :end_time")
            params["end_time"] = end_time
            
        if search:
            try: tokens = shlex.split(search)
            except: tokens = search.split(" ")
            core_fields = {"decky": "decky", "service": "service", "event": "event_type", "attacker": "attacker_ip"}
            for i, token in enumerate(tokens):
                if ":" in token:
                    k, v = token.split(":", 1)
                    if k in core_fields:
                        where_clauses.append(f"{core_fields[k]} = :val_{i}")
                        params[f"val_{i}"] = v
                    else:
                        ks = re.sub(r'[^a-zA-Z0-9_]', '', k)
                        where_clauses.append(f"json_extract(fields, '$.{ks}') = :val_{i}")
                        params[f"val_{i}"] = v
                else:
                    where_clauses.append(f"(raw_line LIKE :lk_{i} OR decky LIKE :lk_{i} OR service LIKE :lk_{i} OR attacker_ip LIKE :lk_{i})")
                    params[f"lk_{i}"] = f"%{token}%"
        
        where = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        return where, params

    async def get_stats_summary(self) -> dict[str, Any]:
        async with self.session_factory() as session:
            total_logs = (await session.execute(select(func.count()).select_from(Log))).scalar() or 0
            unique_attackers = (await session.execute(select(func.count(func.distinct(Log.attacker_ip))))).scalar() or 0
            active_deckies = (await session.execute(select(func.count(func.distinct(Log.decky))))).scalar() or 0
            
            _state = load_state()
            deployed_deckies = len(_state[0].deckies) if _state else 0

            return {
                "total_logs": total_logs,
                "unique_attackers": unique_attackers,
                "active_deckies": active_deckies,
                "deployed_deckies": deployed_deckies
            }

    async def get_deckies(self) -> List[dict]:
        _state = load_state()
        return [_d.model_dump() for _d in _state[0].deckies] if _state else []

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        async with self.session_factory() as session:
            statement = select(User).where(User.username == username)
            results = await session.execute(statement)
            user = results.scalar_one_or_none()
            return user.dict() if user else None

    async def get_user_by_uuid(self, uuid: str) -> Optional[dict]:
        async with self.session_factory() as session:
            statement = select(User).where(User.uuid == uuid)
            results = await session.execute(statement)
            user = results.scalar_one_or_none()
            return user.dict() if user else None

    async def create_user(self, user_data: dict[str, Any]) -> None:
        user = User(**user_data)
        async with self.session_factory() as session:
            session.add(user)
            await session.commit()

    async def update_user_password(self, uuid: str, password_hash: str, must_change_password: bool = False) -> None:
        async with self.session_factory() as session:
            statement = update(User).where(User.uuid == uuid).values(
                password_hash=password_hash,
                must_change_password=must_change_password
            )
            await session.execute(statement)
            await session.commit()

    async def add_bounty(self, bounty_data: dict[str, Any]) -> None:
        data = bounty_data.copy()
        if "payload" in data and isinstance(data["payload"], dict):
            data["payload"] = json.dumps(data["payload"])
        
        bounty = Bounty(**data)
        async with self.session_factory() as session:
            session.add(bounty)
            await session.commit()

    def _apply_bounty_filters(self, statement, bounty_type: Optional[str], search: Optional[str]):
        if bounty_type:
            statement = statement.where(Bounty.bounty_type == bounty_type)
        if search:
            lk = f"%{search}%"
            statement = statement.where(
                or_(
                    Bounty.decky.like(lk),
                    Bounty.service.like(lk),
                    Bounty.attacker_ip.like(lk),
                    Bounty.payload.like(lk)
                )
            )
        return statement

    async def get_bounties(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        bounty_type: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[dict]:
        statement = select(Bounty).order_by(desc(Bounty.timestamp)).offset(offset).limit(limit)
        statement = self._apply_bounty_filters(statement, bounty_type, search)

        async with self.session_factory() as session:
            results = await session.execute(statement)
            items = results.scalars().all()
            final = []
            for item in items:
                d = item.dict()
                try: d["payload"] = json.loads(d["payload"])
                except: pass
                final.append(d)
            return final

    async def get_total_bounties(self, bounty_type: Optional[str] = None, search: Optional[str] = None) -> int:
        statement = select(func.count()).select_from(Bounty)
        statement = self._apply_bounty_filters(statement, bounty_type, search)

        async with self.session_factory() as session:
            result = await session.execute(statement)
            return result.scalar() or 0
