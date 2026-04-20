"""
Shared SQLModel-based repository implementation.

Contains all dialect-portable query code used by the SQLite and MySQL
backends.  Dialect-specific behavior lives in subclasses:

* engine/session construction (``__init__``)
* ``_migrate_attackers_table`` (legacy schema check; DDL introspection
  is not portable)
* ``get_log_histogram`` (date-bucket expression differs per dialect)
"""
from __future__ import annotations

import asyncio
import json

import orjson
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, List

from sqlalchemy import func, select, desc, asc, text, or_, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlmodel.sql.expression import SelectOfScalar

from decnet.config import load_state
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import get_password_hash
from decnet.web.db.repository import BaseRepository
from decnet.web.db.models import (
    User,
    Log,
    Bounty,
    State,
    Attacker,
    AttackerBehavior,
    SwarmHost,
    DeckyShard,
)


from contextlib import asynccontextmanager

from decnet.logging import get_logger

_log = get_logger("db.pool")

# Hold strong refs to in-flight cleanup tasks so they aren't GC'd mid-run.
_cleanup_tasks: set[asyncio.Task] = set()


def _detach_close(session: AsyncSession) -> None:
    """Hand session cleanup to a fresh task so the caller's cancellation
    doesn't interrupt it.

    ``asyncio.shield`` doesn't help on the exception path: shield prevents
    *other* tasks from cancelling the inner coroutine, but if the *current*
    task is already cancelled, its next ``await`` re-raises
    ``CancelledError`` as soon as the inner coroutine yields.  That's what
    happens when uvicorn cancels a request mid-query — the rollback inside
    ``session.close()`` can't complete, and the aiomysql connection is
    orphaned (pool logs "non-checked-in connection" on GC).

    A fresh task isn't subject to the caller's pending cancellation, so
    ``close()`` (or the ``invalidate()`` fallback for a dead connection)
    runs to completion and the pool reclaims the connection promptly.

    Fire-and-forget on purpose: the caller is already unwinding and must
    not wait on cleanup.
    """
    async def _cleanup() -> None:
        try:
            await session.close()
        except BaseException:
            try:
                session.sync_session.invalidate()
            except BaseException:
                _log.debug("detach-close: invalidate failed", exc_info=True)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (shutdown path) — best-effort sync invalidate.
        try:
            session.sync_session.invalidate()
        except BaseException:
            _log.debug("detach-close: no-loop invalidate failed", exc_info=True)
        return
    task = loop.create_task(_cleanup())
    _cleanup_tasks.add(task)
    # Consume any exception to silence "Task exception was never retrieved".
    task.add_done_callback(lambda t: (_cleanup_tasks.discard(t), t.exception()))


@asynccontextmanager
async def _safe_session(factory: async_sessionmaker[AsyncSession]):
    """Session context manager that keeps close() reliable under cancellation.

    Success path: await close() inline so the caller observes cleanup
    (commit visibility, connection release) before proceeding.

    Exception path (includes CancelledError from client disconnects):
    detach close() to a fresh task.  The caller is unwinding and its
    own cancellation would abort an inline close mid-rollback, leaving
    the aiomysql connection orphaned.
    """
    session = factory()
    try:
        yield session
    except BaseException:
        _detach_close(session)
        raise
    else:
        await session.close()


class SQLModelRepository(BaseRepository):
    """Concrete SQLModel/SQLAlchemy-async repository.

    Subclasses provide ``self.engine`` (AsyncEngine) and ``self.session_factory``
    in ``__init__``, and override the few dialect-specific helpers.
    """

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]

    def _session(self):
        """Return a cancellation-safe session context manager."""
        return _safe_session(self.session_factory)

    # ------------------------------------------------------------ lifecycle

    async def initialize(self) -> None:
        """Create tables if absent and seed the admin user."""
        from sqlmodel import SQLModel
        await self._migrate_attackers_table()
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        await self._ensure_admin_user()

    async def reinitialize(self) -> None:
        """Re-create schema (for tests / reset flows). Does NOT drop existing tables."""
        from sqlmodel import SQLModel
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        await self._ensure_admin_user()

    async def _ensure_admin_user(self) -> None:
        async with self._session() as session:
            result = await session.execute(
                select(User).where(User.username == DECNET_ADMIN_USER)
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                session.add(User(
                    uuid=str(uuid.uuid4()),
                    username=DECNET_ADMIN_USER,
                    password_hash=get_password_hash(DECNET_ADMIN_PASSWORD),
                    role="admin",
                    must_change_password=True,
                ))
                await session.commit()
                return
            # Self-heal env drift: if admin never finalized their password,
            # re-sync the hash from DECNET_ADMIN_PASSWORD. Otherwise leave
            # the user's chosen password alone.
            if existing.must_change_password:
                existing.password_hash = get_password_hash(DECNET_ADMIN_PASSWORD)
                session.add(existing)
                await session.commit()

    async def _migrate_attackers_table(self) -> None:
        """Legacy-schema cleanup. Override per dialect (DDL introspection is non-portable)."""
        return None

    # ---------------------------------------------------------------- logs

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
                                self._json_field_equals(key_safe)
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
            select(Log).where(Log.id > last_id).order_by(asc(Log.id)).limit(limit)
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

    # --------------------------------------------------------------- users

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        async with self._session() as session:
            result = await session.execute(
                select(User).where(User.username == username)
            )
            user = result.scalar_one_or_none()
            return user.model_dump() if user else None

    async def get_user_by_uuid(self, uuid: str) -> Optional[dict]:
        async with self._session() as session:
            result = await session.execute(
                select(User).where(User.uuid == uuid)
            )
            user = result.scalar_one_or_none()
            return user.model_dump() if user else None

    async def create_user(self, user_data: dict[str, Any]) -> None:
        async with self._session() as session:
            session.add(User(**user_data))
            await session.commit()

    async def update_user_password(
        self, uuid: str, password_hash: str, must_change_password: bool = False
    ) -> None:
        async with self._session() as session:
            await session.execute(
                update(User)
                .where(User.uuid == uuid)
                .values(
                    password_hash=password_hash,
                    must_change_password=must_change_password,
                )
            )
            await session.commit()

    async def list_users(self) -> list[dict]:
        async with self._session() as session:
            result = await session.execute(select(User))
            return [u.model_dump() for u in result.scalars().all()]

    async def delete_user(self, uuid: str) -> bool:
        async with self._session() as session:
            result = await session.execute(select(User).where(User.uuid == uuid))
            user = result.scalar_one_or_none()
            if not user:
                return False
            await session.delete(user)
            await session.commit()
            return True

    async def update_user_role(self, uuid: str, role: str) -> None:
        async with self._session() as session:
            await session.execute(
                update(User).where(User.uuid == uuid).values(role=role)
            )
            await session.commit()

    async def purge_logs_and_bounties(self) -> dict[str, int]:
        async with self._session() as session:
            logs_deleted = (await session.execute(text("DELETE FROM logs"))).rowcount
            bounties_deleted = (await session.execute(text("DELETE FROM bounty"))).rowcount
            # attacker_behavior has FK → attackers.uuid; delete children first.
            await session.execute(text("DELETE FROM attacker_behavior"))
            attackers_deleted = (await session.execute(text("DELETE FROM attackers"))).rowcount
            await session.commit()
        return {
            "logs": logs_deleted,
            "bounties": bounties_deleted,
            "attackers": attackers_deleted,
        }

    # ------------------------------------------------------------ bounties

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

    async def get_state(self, key: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()
            if state:
                return json.loads(state.value)
            return None

    async def set_state(self, key: str, value: Any) -> None:  # noqa: ANN401
        async with self._session() as session:
            statement = select(State).where(State.key == key)
            result = await session.execute(statement)
            state = result.scalar_one_or_none()

            value_json = orjson.dumps(value).decode()
            if state:
                state.value = value_json
                session.add(state)
            else:
                session.add(State(key=key, value=value_json))

            await session.commit()

    # ----------------------------------------------------------- attackers

    async def get_all_bounties_by_ip(self) -> dict[str, List[dict[str, Any]]]:
        from collections import defaultdict
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
        from collections import defaultdict
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

    async def upsert_attacker(self, data: dict[str, Any]) -> str:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker).where(Attacker.ip == data["ip"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
                session.add(existing)
                row_uuid = existing.uuid
            else:
                row_uuid = str(uuid.uuid4())
                data = {**data, "uuid": row_uuid}
                session.add(Attacker(**data))
            await session.commit()
            return row_uuid

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
                select(Attacker.ip, AttackerBehavior)
                .join(AttackerBehavior, Attacker.uuid == AttackerBehavior.attacker_uuid)
                .where(Attacker.ip.in_(ips))
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
        return d

    @staticmethod
    def _deserialize_attacker(d: dict[str, Any]) -> dict[str, Any]:
        for key in ("services", "deckies", "fingerprints", "commands"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    async def get_attacker_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
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
        service: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        order = {
            "active": desc(Attacker.event_count),
            "traversals": desc(Attacker.is_traversal),
        }.get(sort_by, desc(Attacker.last_seen))

        statement = select(Attacker).order_by(order).offset(offset).limit(limit)
        if search:
            statement = statement.where(Attacker.ip.like(f"%{search}%"))
        if service:
            statement = statement.where(Attacker.services.like(f'%"{service}"%'))

        async with self._session() as session:
            result = await session.execute(statement)
            return [
                self._deserialize_attacker(a.model_dump(mode="json"))
                for a in result.scalars().all()
            ]

    async def get_total_attackers(
        self, search: Optional[str] = None, service: Optional[str] = None
    ) -> int:
        statement = select(func.count()).select_from(Attacker)
        if search:
            statement = statement.where(Attacker.ip.like(f"%{search}%"))
        if service:
            statement = statement.where(Attacker.services.like(f'%"{service}"%'))

        async with self._session() as session:
            result = await session.execute(statement)
            return result.scalar() or 0

    async def get_attacker_commands(
        self,
        uuid: str,
        limit: int = 50,
        offset: int = 0,
        service: Optional[str] = None,
    ) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.execute(
                select(Attacker.commands).where(Attacker.uuid == uuid)
            )
            raw = result.scalar_one_or_none()
            if raw is None:
                return {"total": 0, "data": []}

            commands: list = json.loads(raw) if isinstance(raw, str) else raw
            if service:
                commands = [c for c in commands if c.get("service") == service]

            total = len(commands)
            page = commands[offset: offset + limit]
            return {"total": total, "data": page}

    async def get_attacker_artifacts(self, uuid: str) -> list[dict[str, Any]]:
        """Return `file_captured` logs for the attacker identified by UUID.

        Resolves the attacker's IP first, then queries the logs table on two
        indexed columns (``attacker_ip`` and ``event_type``). No JSON extract
        needed — the decky/stored_as are already decoded into ``fields`` by
        the ingester and returned to the frontend for drawer rendering.
        """
        async with self._session() as session:
            ip_res = await session.execute(
                select(Attacker.ip).where(Attacker.uuid == uuid)
            )
            ip = ip_res.scalar_one_or_none()
            if not ip:
                return []
            rows = await session.execute(
                select(Log)
                .where(Log.attacker_ip == ip)
                .where(Log.event_type == "file_captured")
                .order_by(desc(Log.timestamp))
                .limit(200)
            )
            return [r.model_dump(mode="json") for r in rows.scalars().all()]

    # ------------------------------------------------------------- swarm

    async def add_swarm_host(self, data: dict[str, Any]) -> None:
        async with self._session() as session:
            session.add(SwarmHost(**data))
            await session.commit()

    async def get_swarm_host_by_name(self, name: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(select(SwarmHost).where(SwarmHost.name == name))
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def get_swarm_host_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with self._session() as session:
            result = await session.execute(select(SwarmHost).where(SwarmHost.uuid == uuid))
            row = result.scalar_one_or_none()
            return row.model_dump(mode="json") if row else None

    async def list_swarm_hosts(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        statement = select(SwarmHost).order_by(asc(SwarmHost.name))
        if status:
            statement = statement.where(SwarmHost.status == status)
        async with self._session() as session:
            result = await session.execute(statement)
            return [r.model_dump(mode="json") for r in result.scalars().all()]

    async def update_swarm_host(self, uuid: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        async with self._session() as session:
            await session.execute(
                update(SwarmHost).where(SwarmHost.uuid == uuid).values(**fields)
            )
            await session.commit()

    async def delete_swarm_host(self, uuid: str) -> bool:
        async with self._session() as session:
            # Clean up child shards first (no ON DELETE CASCADE portable across dialects).
            await session.execute(
                text("DELETE FROM decky_shards WHERE host_uuid = :u"), {"u": uuid}
            )
            result = await session.execute(
                select(SwarmHost).where(SwarmHost.uuid == uuid)
            )
            host = result.scalar_one_or_none()
            if not host:
                await session.commit()
                return False
            await session.delete(host)
            await session.commit()
            return True

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
