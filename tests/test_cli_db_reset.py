"""
Tests for the `decnet db-reset` CLI command.

No live MySQL required — the async worker is mocked.
"""
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from decnet.cli import app, _db_reset_mysql_async


runner = CliRunner()


# ── Guard-rails ───────────────────────────────────────────────────────────────

class TestDbResetGuards:
    def test_refuses_when_backend_is_sqlite(self, monkeypatch):
        monkeypatch.setenv("DECNET_DB_TYPE", "sqlite")
        result = runner.invoke(app, ["db-reset", "--i-know-what-im-doing"])
        assert result.exit_code == 2
        assert "MySQL-only" in result.stdout

    def test_refuses_invalid_mode(self, monkeypatch):
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        result = runner.invoke(app, ["db-reset", "--mode", "nuke"])
        assert result.exit_code == 2
        assert "Invalid --mode" in result.stdout

    def test_reports_missing_connection_info(self, monkeypatch):
        """With no URL and no component env vars, build_mysql_url raises — surface it."""
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        for v in ("DECNET_DB_URL", "DECNET_DB_PASSWORD"):
            monkeypatch.delenv(v, raising=False)
        # Strip pytest env so build_mysql_url's safety check trips (needs a
        # password when we're "not in tests" per its own heuristic).
        import os
        for k in list(os.environ):
            if k.startswith("PYTEST"):
                monkeypatch.delenv(k, raising=False)

        result = runner.invoke(app, ["db-reset"])
        assert result.exit_code == 2
        assert "DECNET_DB_PASSWORD" in result.stdout


# ── Dry-run vs. confirmed execution ───────────────────────────────────────────

class TestDbResetDispatch:
    def test_dry_run_skips_destructive_phase(self, monkeypatch):
        """Without the flag, the command must still call into the worker
        (to show row counts) but signal confirm=False."""
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        monkeypatch.setenv("DECNET_DB_URL", "mysql+aiomysql://u:p@h/d")

        mock = AsyncMock()
        with patch("decnet.cli._db_reset_mysql_async", new=mock):
            result = runner.invoke(app, ["db-reset"])

        assert result.exit_code == 0, result.stdout
        mock.assert_awaited_once()
        kwargs = mock.await_args.kwargs
        assert kwargs["confirm"] is False
        assert kwargs["mode"] == "truncate"

    def test_confirmed_execution_passes_confirm_true(self, monkeypatch):
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        monkeypatch.setenv("DECNET_DB_URL", "mysql+aiomysql://u:p@h/d")

        mock = AsyncMock()
        with patch("decnet.cli._db_reset_mysql_async", new=mock):
            result = runner.invoke(app, ["db-reset", "--i-know-what-im-doing"])

        assert result.exit_code == 0, result.stdout
        assert mock.await_args.kwargs["confirm"] is True

    def test_drop_tables_mode_propagates(self, monkeypatch):
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        monkeypatch.setenv("DECNET_DB_URL", "mysql+aiomysql://u:p@h/d")

        mock = AsyncMock()
        with patch("decnet.cli._db_reset_mysql_async", new=mock):
            result = runner.invoke(
                app, ["db-reset", "--mode", "drop-tables", "--i-know-what-im-doing"]
            )

        assert result.exit_code == 0, result.stdout
        assert mock.await_args.kwargs["mode"] == "drop-tables"

    def test_explicit_url_overrides_env(self, monkeypatch):
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        monkeypatch.setenv("DECNET_DB_URL", "mysql+aiomysql://from-env/db")

        mock = AsyncMock()
        with patch("decnet.cli._db_reset_mysql_async", new=mock):
            result = runner.invoke(app, [
                "db-reset", "--url", "mysql+aiomysql://override/db2",
            ])

        assert result.exit_code == 0, result.stdout
        # First positional arg to the async worker is the DSN.
        assert mock.await_args.args[0] == "mysql+aiomysql://override/db2"


# ── Destructive-phase skip when flag is absent ───────────────────────────────

class TestDbResetWorker:
    @pytest.mark.anyio
    async def test_dry_run_does_not_open_begin_transaction(self):
        """Confirm=False must stop after the row-count inspection — no DDL/DML."""
        from unittest.mock import MagicMock

        mock_conn = AsyncMock()
        # Every table shows as "missing" so row-count loop exits cleanly.
        mock_conn.execute.side_effect = Exception("no such table")

        mock_connect_cm = AsyncMock()
        mock_connect_cm.__aenter__.return_value = mock_conn
        mock_connect_cm.__aexit__.return_value = False

        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_connect_cm
        mock_engine.begin = MagicMock()  # must NOT be awaited in dry-run
        mock_engine.dispose = AsyncMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=mock_engine):
            await _db_reset_mysql_async(
                "mysql+aiomysql://u:p@h/d", mode="truncate", confirm=False
            )

        mock_engine.begin.assert_not_called()
        mock_engine.dispose.assert_awaited_once()
