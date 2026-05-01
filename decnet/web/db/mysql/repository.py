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

    async def _migrate_attackers_table(self) -> None:
        """Drop the legacy (pre-UUID) ``attackers`` table if it exists without a ``uuid`` column.

        Also adds the GeoIP columns (``country_code``, ``country_source``)
        to existing tables that predate them. MySQL exposes column
        metadata via ``information_schema.COLUMNS``; ``DATABASE()`` scopes
        the lookup to the currently connected schema.
        """
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'attackers'"
            ))).fetchall()
            if not rows:
                return  # table absent; create_all() handles it.
            if not any(r[0] == "uuid" for r in rows):
                await conn.execute(text("DROP TABLE attackers"))
                return
            existing_cols = {r[0] for r in rows}
            if "country_code" not in existing_cols:
                await conn.execute(text(
                    "ALTER TABLE attackers "
                    "ADD COLUMN country_code VARCHAR(2) NULL, "
                    "ADD INDEX ix_attackers_country_code (country_code)"
                ))
            if "country_source" not in existing_cols:
                await conn.execute(text(
                    "ALTER TABLE attackers ADD COLUMN country_source VARCHAR(16) NULL"
                ))

    async def _migrate_column_types(self) -> None:
        """Upgrade TEXT → MEDIUMTEXT for columns that accumulate large JSON blobs.

        ``create_all()`` never alters existing columns, so tables created before
        ``_BIG_TEXT`` was introduced keep their 64 KiB ``TEXT`` cap.  This method
        inspects ``information_schema`` and issues ``ALTER TABLE … MODIFY COLUMN``
        for each offending column found.
        """
        targets: dict[str, dict[str, str]] = {
            "attackers": {
                "commands":     "MEDIUMTEXT NOT NULL DEFAULT '[]'",
                "fingerprints": "MEDIUMTEXT NOT NULL DEFAULT '[]'",
                "services":     "MEDIUMTEXT NOT NULL DEFAULT '[]'",
                "deckies":      "MEDIUMTEXT NOT NULL DEFAULT '[]'",
            },
            "state": {
                "value": "MEDIUMTEXT NOT NULL",
            },
        }
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text(
                "SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "  AND TABLE_NAME  IN ('attackers', 'state') "
                "  AND COLUMN_NAME IN ('commands','fingerprints','services','deckies','value') "
                "  AND DATA_TYPE   = 'text'"
            ))).fetchall()
            for table_name, col_name in rows:
                spec = targets.get(table_name, {}).get(col_name)
                if spec:
                    await conn.execute(text(
                        f"ALTER TABLE `{table_name}` MODIFY COLUMN `{col_name}` {spec}"
                    ))

    async def _migrate_session_profile_table(self) -> None:
        """Add DEBT-036 keystroke-dynamics columns (start-of-action latency,
        three-bucket pause histogram, top-bigrams JSON) to existing tables.

        MySQL's ``ALTER TABLE ADD COLUMN`` fails if the column already
        exists, so gate on ``information_schema.COLUMNS`` to stay
        idempotent.
        """
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'session_profile'"
            ))).fetchall()
            if not rows:
                return
            existing_cols = {r[0] for r in rows}
            additions = [
                ("kd_top_bigrams", "TEXT NULL"),
                ("kd_start_of_action_latency", "DOUBLE NULL"),
                ("kd_pause_hist_burst", "INT NULL"),
                ("kd_pause_hist_think", "INT NULL"),
                ("kd_pause_hist_distracted", "INT NULL"),
            ]
            for col_name, col_spec in additions:
                if col_name not in existing_cols:
                    await conn.execute(text(
                        f"ALTER TABLE session_profile ADD COLUMN {col_name} {col_spec}"
                    ))

    async def initialize(self) -> None:
        """Create tables and run all MySQL-specific migrations.

        Uses a MySQL advisory lock to serialize DDL across concurrent
        uvicorn workers — prevents the 'Table was skipped since its
        definition is being modified by concurrent DDL' race.
        """
        from sqlmodel import SQLModel
        async with self.engine.connect() as lock_conn:
            await lock_conn.execute(text("SELECT GET_LOCK('decnet_schema_init', 30)"))
            try:
                await self._migrate_attackers_table()
                await self._migrate_session_profile_table()
                await self._migrate_column_types()
                async with self.engine.begin() as conn:
                    await conn.run_sync(SQLModel.metadata.create_all)
                await self._ensure_admin_user()
            finally:
                await lock_conn.execute(text("SELECT RELEASE_LOCK('decnet_schema_init')"))
                await lock_conn.close()

    def _json_field_equals(self, key: str):
        # MySQL 5.7+ exposes JSON_EXTRACT; quoted string result returned for
        # TEXT-stored JSON, same behavior we rely on in SQLite.
        return text(f"JSON_UNQUOTE(JSON_EXTRACT(fields, '$.{key}')) = :val")

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
