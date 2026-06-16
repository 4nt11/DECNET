# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any, List, Optional

from sqlalchemy import func, select, text, literal_column
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


from decnet.config import _ROOT
from decnet.web.db.models import Log, TTPTag
from decnet.web.db.sqlite.database import get_async_engine
from decnet.web.db.sqlmodel_repo import SQLModelRepository


class SQLiteRepository(SQLModelRepository):
    """SQLite backend — uses ``aiosqlite``.

    Overrides the one place where SQLite's SQL dialect differs from
    MySQL/PostgreSQL: the log-histogram bucket expression (via ``strftime``
    + ``unixepoch``). Schema is managed by Alembic (see db/migrate.py).
    """

    def __init__(self, db_path: str = str(_ROOT / "decnet.db")) -> None:
        self.db_path = db_path
        self.engine = get_async_engine(db_path)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    def _json_field_equals(self, key: str, param_name: str = "val"):
        # SQLite stores JSON as text; json_extract is the canonical accessor.
        return text(f"json_extract(fields, '$.{key}') = :{param_name}")

    async def _insert_tags_or_ignore(self, rows: list[TTPTag]) -> int:
        """Bulk-insert with SQLite's ``ON CONFLICT DO NOTHING`` on the
        ``uuid`` PK. Returns rowcount of newly-inserted rows; the
        skipped duplicates do not count.
        """
        if not rows:
            return 0
        payload = [r.model_dump() for r in rows]
        stmt = sqlite_insert(TTPTag.__table__).values(payload)  # type: ignore[attr-defined]
        stmt = stmt.on_conflict_do_nothing(index_elements=["uuid"])
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
        bucket_expr: Any = literal_column(
            f"datetime((strftime('%s', timestamp) / {bucket_seconds}) * {bucket_seconds}, 'unixepoch')"
        ).label("bucket_time")

        statement: Any = select(bucket_expr, func.count().label("count")).select_from(Log)
        statement = self._apply_filters(statement, search, start_time, end_time)
        statement = statement.group_by(literal_column("bucket_time")).order_by(
            literal_column("bucket_time")
        )

        async with self._session() as session:
            results = await session.execute(statement)
            return [{"time": r[0], "count": r[1]} for r in results.all()]
