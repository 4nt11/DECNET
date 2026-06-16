# SPDX-License-Identifier: AGPL-3.0-or-later
"""
MySQL implementation of :class:`BaseRepository`.

Inherits the portable SQLModel query code from :class:`SQLModelRepository`
and only overrides where MySQL's SQL dialect differs from SQLite's:

* :meth:`_apply_schema`     — wraps the Alembic upgrade in a MySQL advisory
  lock to serialize DDL across concurrent workers.
* :meth:`get_log_histogram` — uses ``FROM_UNIXTIME`` / ``UNIX_TIMESTAMP`` +
  integer division for bucketing.
"""
from __future__ import annotations

from typing import Any, List, Optional

from sqlalchemy import func, select, text, literal_column
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


from decnet.web.db.models import Log, TTPTag
from decnet.web.db.mysql.database import get_async_engine
from decnet.web.db.sqlmodel_repo import SQLModelRepository


class MySQLRepository(SQLModelRepository):
    """MySQL backend — uses ``asyncmy``."""

    def __init__(self, url: Optional[str] = None, **engine_kwargs) -> None:
        self.engine = get_async_engine(url=url, **engine_kwargs)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def _apply_schema(self) -> None:
        """Run the Alembic upgrade under a MySQL advisory lock.

        The lock serializes DDL across concurrent uvicorn workers — Alembic
        does not lock MySQL DDL itself, so without it parallel workers race
        ('Table was skipped since its definition is being modified by
        concurrent DDL'). Tests (``DECNET_TESTING=1``) take the base
        ``create_all`` path, which is single-process and needs no lock.
        """
        import os
        if os.environ.get("DECNET_TESTING") == "1":
            await super()._apply_schema()
            return
        from decnet.web.db.migrate import run_migrations
        async with self.engine.connect() as lock_conn:
            await lock_conn.execute(text("SELECT GET_LOCK('decnet_schema_init', 30)"))
            try:
                await run_migrations(self.engine)
            finally:
                await lock_conn.execute(text("SELECT RELEASE_LOCK('decnet_schema_init')"))
                await lock_conn.close()

    def _json_field_equals(self, key: str, param_name: str = "val"):
        # MySQL 5.7+ exposes JSON_EXTRACT; quoted string result returned for
        # TEXT-stored JSON, same behavior we rely on in SQLite.
        return text(f"JSON_UNQUOTE(JSON_EXTRACT(fields, '$.{key}')) = :{param_name}")

    async def _insert_tags_or_ignore(self, rows: list[TTPTag]) -> int:
        """Bulk-insert with MySQL's ``INSERT IGNORE`` on the ``uuid`` PK.

        ``rowcount`` returns the number of NEW rows; duplicates are
        silently ignored (matching the SQLite ``ON CONFLICT DO NOTHING``
        contract).
        """
        if not rows:
            return 0
        payload = [r.model_dump() for r in rows]
        stmt = (
            mysql_insert(TTPTag.__table__)  # type: ignore[attr-defined]
            .values(payload)
            .prefix_with("IGNORE")
        )
        async with self._session() as session:
            result = await session.execute(stmt)
            await session.commit()
            return int(result.rowcount or 0)

    async def get_log_histogram(
        self,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interval_minutes: int = 15,
    ) -> List[dict]:
        bucket_seconds = max(interval_minutes, 1) * 60
        # Truncate each timestamp to the start of its bucket:
        #   FROM_UNIXTIME( (UNIX_TIMESTAMP(timestamp) DIV N) * N )
        # DIV is MySQL's integer division operator.
        bucket_expr: Any = literal_column(
            f"FROM_UNIXTIME((UNIX_TIMESTAMP(timestamp) DIV {bucket_seconds}) * {bucket_seconds})"
        ).label("bucket_time")

        statement: Any = select(bucket_expr, func.count().label("count")).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)
        statement = statement.group_by(literal_column("bucket_time")).order_by(
            literal_column("bucket_time")
        )

        async with self._session() as session:
            results = await session.execute(statement)
            # Normalize to ISO string for API parity with the SQLite backend
            # (SQLite's datetime() returns a string already; FROM_UNIXTIME
            # returns a datetime).
            out: List[dict] = []
            for r in results.all():
                ts = r[0]
                out.append({
                    "time": ts.isoformat(sep=" ") if hasattr(ts, "isoformat") else ts,
                    "count": r[1],
                })
            return out
