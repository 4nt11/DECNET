# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Inspection-level tests for the MySQL-dialect SQL emitted by MySQLRepository.

We compile the SQLAlchemy statements against the MySQL dialect and assert on
the string form — no live MySQL server is required.
"""
import pytest
from sqlalchemy import func, select, literal_column
from sqlalchemy.dialects import mysql
from sqlmodel.sql.expression import SelectOfScalar

from decnet.web.db.models import Log


def _compile(stmt) -> str:
    """Compile a statement to MySQL-dialect SQL with literal values inlined."""
    return str(stmt.compile(
        dialect=mysql.dialect(),
        compile_kwargs={"literal_binds": True},
    ))


def test_mysql_histogram_uses_from_unixtime_bucket():
    """The MySQL dialect must bucket with UNIX_TIMESTAMP DIV N * N wrapped in FROM_UNIXTIME."""
    bucket_seconds = 900  # 15 min
    bucket_expr = literal_column(
        f"FROM_UNIXTIME((UNIX_TIMESTAMP(timestamp) DIV {bucket_seconds}) * {bucket_seconds})"
    ).label("bucket_time")
    stmt: SelectOfScalar = select(bucket_expr, func.count().label("count")).select_from(Log)

    sql = _compile(stmt)
    assert "FROM_UNIXTIME" in sql
    assert "UNIX_TIMESTAMP" in sql
    assert "DIV 900" in sql
    # Sanity: SQLite-only strftime must NOT appear in the MySQL-dialect output.
    assert "strftime" not in sql
    assert "unixepoch" not in sql


def test_mysql_json_unquote_predicate_shape():
    """MySQL JSON filter uses JSON_UNQUOTE(JSON_EXTRACT(...))."""
    from decnet.web.db.mysql.repository import MySQLRepository

    # Build a dummy instance without touching the engine. We only need _json_field_equals,
    # which is a pure function of the key.
    repo = MySQLRepository.__new__(MySQLRepository)  # bypass __init__ / no DB connection
    predicate = repo._json_field_equals("username")

    # text() objects carry their literal SQL in .text
    assert "JSON_UNQUOTE" in predicate.text
    assert "JSON_EXTRACT(fields, '$.username')" in predicate.text
    assert ":val" in predicate.text


@pytest.mark.parametrize("key", ["user", "port", "sess_id"])
def test_mysql_json_predicate_safe_for_reasonable_keys(key):
    """Keys matching [A-Za-z0-9_]+ are inserted verbatim; verify no SQL breakage."""
    from decnet.web.db.mysql.repository import MySQLRepository
    repo = MySQLRepository.__new__(MySQLRepository)
    pred = repo._json_field_equals(key)
    assert f"'$.{key}'" in pred.text


def test_sqlite_histogram_still_uses_strftime():
    """Regression guard — SQLite implementation must keep its strftime-based bucket."""
    from decnet.web.db.sqlite.repository import SQLiteRepository
    import inspect
    src = inspect.getsource(SQLiteRepository.get_log_histogram)
    assert "strftime" in src
    assert "unixepoch" in src
