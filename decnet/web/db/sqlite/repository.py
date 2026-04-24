from typing import List, Optional

from sqlalchemy import func, select, text, literal_column
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel.sql.expression import SelectOfScalar

from decnet.config import _ROOT
from decnet.web.db.models import Log
from decnet.web.db.sqlite.database import get_async_engine
from decnet.web.db.sqlmodel_repo import SQLModelRepository


class SQLiteRepository(SQLModelRepository):
    """SQLite backend — uses ``aiosqlite``.

    Overrides the two places where SQLite's SQL dialect differs from
    MySQL/PostgreSQL: legacy-schema migration (via ``PRAGMA table_info``)
    and the log-histogram bucket expression (via ``strftime`` + ``unixepoch``).
    """

    def __init__(self, db_path: str = str(_ROOT / "decnet.db")) -> None:
        self.db_path = db_path
        self.engine = get_async_engine(db_path)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def _migrate_attackers_table(self) -> None:
        """Drop the old attackers table if it lacks the uuid column (pre-UUID schema).

        Also adds the GeoIP columns (``country_code``, ``country_source``)
        to existing tables that predate them. SQLite's
        ``ALTER TABLE ADD COLUMN`` is idempotent only if we gate on
        ``PRAGMA table_info`` first — re-adding raises.
        """
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text("PRAGMA table_info(attackers)"))).fetchall()
            if rows and not any(r[1] == "uuid" for r in rows):
                await conn.execute(text("DROP TABLE attackers"))
                return  # create_all() rebuilds fresh — no need to patch columns.
            if not rows:
                return  # table absent; create_all() handles it.
            existing_cols = {r[1] for r in rows}
            if "country_code" not in existing_cols:
                await conn.execute(text(
                    "ALTER TABLE attackers ADD COLUMN country_code VARCHAR(2)"
                ))
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_attackers_country_code "
                    "ON attackers (country_code)"
                ))
            if "country_source" not in existing_cols:
                await conn.execute(text(
                    "ALTER TABLE attackers ADD COLUMN country_source VARCHAR(16)"
                ))

    def _json_field_equals(self, key: str):
        # SQLite stores JSON as text; json_extract is the canonical accessor.
        return text(f"json_extract(fields, '$.{key}') = :val")

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

        statement: SelectOfScalar = select(bucket_expr, func.count().label("count")).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)
        statement = statement.group_by(literal_column("bucket_time")).order_by(
            literal_column("bucket_time")
        )

        async with self._session() as session:
            results = await session.execute(statement)
            return [{"time": r[0], "count": r[1]} for r in results.all()]
