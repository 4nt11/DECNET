"""
MySQL implementation of :class:`BaseRepository`.

Inherits the portable SQLModel query code from :class:`SQLModelRepository`
and only overrides the two places where MySQL's SQL dialect differs from
SQLite's:

* :meth:`_migrate_attackers_table` — uses ``information_schema`` (MySQL
  has no ``PRAGMA``).
* :meth:`get_log_histogram`        — uses ``FROM_UNIXTIME`` /
  ``UNIX_TIMESTAMP`` + integer division for bucketing.
"""
from __future__ import annotations

from typing import List, Optional

from sqlalchemy import func, select, text, literal_column
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel.sql.expression import SelectOfScalar

from decnet.web.db.models import Log
from decnet.web.db.mysql.database import get_async_engine
from decnet.web.db.sqlmodel_repo import SQLModelRepository


class MySQLRepository(SQLModelRepository):
    """MySQL backend — uses ``aiomysql``."""

    def __init__(self, url: Optional[str] = None, **engine_kwargs) -> None:
        self.engine = get_async_engine(url=url, **engine_kwargs)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def _migrate_attackers_table(self) -> None:
        """Drop the legacy (pre-UUID) ``attackers`` table if it exists without a ``uuid`` column.

        MySQL exposes column metadata via ``information_schema.COLUMNS``.
        ``DATABASE()`` scopes the lookup to the currently connected schema.
        """
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'attackers'"
            ))).fetchall()
            if rows and not any(r[0] == "uuid" for r in rows):
                await conn.execute(text("DROP TABLE attackers"))

    def _json_field_equals(self, key: str):
        # MySQL 5.7+ exposes JSON_EXTRACT; quoted string result returned for
        # TEXT-stored JSON, same behavior we rely on in SQLite.
        return text(f"JSON_UNQUOTE(JSON_EXTRACT(fields, '$.{key}')) = :val")

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
        bucket_expr = literal_column(
            f"FROM_UNIXTIME((UNIX_TIMESTAMP(timestamp) DIV {bucket_seconds}) * {bucket_seconds})"
        ).label("bucket_time")

        statement: SelectOfScalar = select(bucket_expr, func.count().label("count")).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)
        statement = statement.group_by(literal_column("bucket_time")).order_by(
            literal_column("bucket_time")
        )

        async with self.session_factory() as session:
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
