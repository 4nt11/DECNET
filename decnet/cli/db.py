from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from .utils import console, log


_DB_RESET_TABLES: tuple[str, ...] = (
    # Order matters for DROP TABLE: child FKs first.
    # - attacker_behavior FK-references attackers.
    # - decky_shards FK-references swarm_hosts.
    # - topology_* children FK-reference topologies / lans / topology_deckies.
    "attacker_behavior",
    "attackers",
    "logs",
    "bounty",
    "state",
    "users",
    "decky_shards",
    "swarm_hosts",
    "topology_status_events",
    "topology_mutations",
    "topology_edges",
    "topology_deckies",
    "lans",
    "topologies",
)


async def _db_reset_mysql_async(dsn: str, mode: str, confirm: bool) -> None:
    """Inspect + (optionally) wipe a MySQL database.  Pulled out of the CLI
    wrapper so tests can drive it without spawning a Typer runner."""
    from urllib.parse import urlparse
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    db_name = urlparse(dsn).path.lstrip("/") or "(default)"
    engine = create_async_engine(dsn)
    try:
        rows: dict[str, int] = {}
        async with engine.connect() as conn:
            for tbl in _DB_RESET_TABLES:
                try:
                    result = await conn.execute(text(f"SELECT COUNT(*) FROM `{tbl}`"))  # nosec B608
                    rows[tbl] = result.scalar() or 0
                except Exception:  # noqa: BLE001 — ProgrammingError for missing table varies by driver
                    rows[tbl] = -1

        summary = Table(title=f"DECNET MySQL reset — database `{db_name}` (mode={mode})")
        summary.add_column("Table", style="cyan")
        summary.add_column("Rows", justify="right")
        for tbl, count in rows.items():
            summary.add_row(tbl, "[dim]missing[/]" if count < 0 else f"{count:,}")
        console.print(summary)

        if not confirm:
            console.print(
                "[yellow]Dry-run only.  Re-run with [bold]--i-know-what-im-doing[/] "
                "to actually execute.[/]"
            )
            return

        async with engine.begin() as conn:
            await conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
            for tbl in _DB_RESET_TABLES:
                if rows.get(tbl, -1) < 0:
                    continue
                if mode == "truncate":
                    await conn.execute(text(f"TRUNCATE TABLE `{tbl}`"))
                    console.print(f"[green]✓ TRUNCATE {tbl}[/]")
                else:
                    await conn.execute(text(f"DROP TABLE `{tbl}`"))
                    console.print(f"[green]✓ DROP TABLE {tbl}[/]")
            await conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))

        console.print(f"[bold green]Done. Database `{db_name}` reset ({mode}).[/]")
    finally:
        await engine.dispose()


def register(app: typer.Typer) -> None:
    @app.command(name="db-reset")
    def db_reset(
        i_know: bool = typer.Option(
            False,
            "--i-know-what-im-doing",
            help="Required to actually execute. Without it, the command runs in dry-run mode.",
        ),
        mode: str = typer.Option(
            "truncate",
            "--mode",
            help="truncate (wipe rows, keep schema) | drop-tables (DROP TABLE for each DECNET table)",
        ),
        url: Optional[str] = typer.Option(
            None,
            "--url",
            help="Override DECNET_DB_URL for this invocation (e.g. when cleanup needs admin creds).",
        ),
    ) -> None:
        """Wipe the MySQL database used by the DECNET dashboard.

        Destructive. Runs dry by default — pass --i-know-what-im-doing to commit.
        Only supported against MySQL; refuses to operate on SQLite.
        """
        import asyncio
        import os

        if mode not in ("truncate", "drop-tables"):
            console.print(f"[red]Invalid --mode '{mode}'. Expected: truncate | drop-tables.[/]")
            raise typer.Exit(2)

        db_type = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()
        if db_type != "mysql":
            console.print(
                f"[red]db-reset is MySQL-only (DECNET_DB_TYPE='{db_type}'). "
                f"For SQLite, just delete the decnet.db file.[/]"
            )
            raise typer.Exit(2)

        dsn = url or os.environ.get("DECNET_DB_URL")
        if not dsn:
            from decnet.web.db.mysql.database import build_mysql_url
            try:
                dsn = build_mysql_url()
            except ValueError as e:
                console.print(f"[red]{e}[/]")
                raise typer.Exit(2) from e

        log.info("db-reset invoked mode=%s confirm=%s", mode, i_know)
        try:
            asyncio.run(_db_reset_mysql_async(dsn, mode=mode, confirm=i_know))
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]db-reset failed: {e}[/]")
            raise typer.Exit(1) from e
