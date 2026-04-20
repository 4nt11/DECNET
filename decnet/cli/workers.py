from __future__ import annotations

from typing import Optional

import typer

from decnet.env import DECNET_INGEST_LOG_FILE

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def probe(
        log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path for RFC 5424 syslog + .json output (reads attackers from .json, writes results to both)"),
        interval: int = typer.Option(300, "--interval", "-i", help="Seconds between probe cycles (default: 300)"),
        timeout: float = typer.Option(5.0, "--timeout", help="Per-probe TCP timeout in seconds"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background (used by deploy, no console output)"),
    ) -> None:
        """Fingerprint attackers (JARM + HASSH + TCP/IP stack) discovered in the log stream."""
        import asyncio
        from decnet.prober import prober_worker

        if daemon:
            log.info("probe daemonizing log_file=%s interval=%d", log_file, interval)
            _utils._daemonize()
            asyncio.run(prober_worker(log_file, interval=interval, timeout=timeout))
            return

        log.info("probe command invoked log_file=%s interval=%d", log_file, interval)
        console.print(f"[bold cyan]DECNET-PROBER[/] watching {log_file} for attackers (interval: {interval}s)")
        console.print("[dim]Press Ctrl+C to stop[/]")
        try:
            asyncio.run(prober_worker(log_file, interval=interval, timeout=timeout))
        except KeyboardInterrupt:
            console.print("\n[yellow]DECNET-PROBER stopped.[/]")

    @app.command()
    def collect(
        log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to write RFC 5424 syslog lines and .json records"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Stream Docker logs from all running decky service containers to a log file."""
        import asyncio
        from decnet.collector import log_collector_worker

        if daemon:
            log.info("collect daemonizing log_file=%s", log_file)
            _utils._daemonize()

        log.info("collect command invoked log_file=%s", log_file)
        console.print(f"[bold cyan]Collector starting[/] → {log_file}")
        asyncio.run(log_collector_worker(log_file))

    @app.command()
    def mutate(
        watch: bool = typer.Option(False, "--watch", "-w", help="Run continuously and mutate deckies according to their interval"),
        decky_name: Optional[str] = typer.Option(None, "--decky", help="Force mutate a specific decky immediately"),
        force_all: bool = typer.Option(False, "--all", help="Force mutate all deckies immediately"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Manually trigger or continuously watch for decky mutation."""
        import asyncio
        from decnet.mutator import mutate_decky, mutate_all, run_watch_loop
        from decnet.web.dependencies import repo

        if daemon:
            log.info("mutate daemonizing watch=%s", watch)
            _utils._daemonize()

        async def _run() -> None:
            await repo.initialize()
            if watch:
                await run_watch_loop(repo)
            elif decky_name:
                await mutate_decky(decky_name, repo)
            elif force_all:
                await mutate_all(force=True, repo=repo)
            else:
                await mutate_all(force=False, repo=repo)

        asyncio.run(_run())

    @app.command(name="correlate")
    def correlate(
        log_file: Optional[str] = typer.Option(None, "--log-file", "-f", help="Path to DECNET syslog file to analyse"),
        min_deckies: int = typer.Option(2, "--min-deckies", "-m", help="Minimum number of distinct deckies an IP must touch to be reported"),
        output: str = typer.Option("table", "--output", "-o", help="Output format: table | json | syslog"),
        emit_syslog: bool = typer.Option(False, "--emit-syslog", help="Also print traversal events as RFC 5424 lines (for SIEM piping)"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Analyse logs for cross-decky traversals and print the attacker movement graph."""
        import sys
        import json as _json
        from pathlib import Path
        from decnet.correlation.engine import CorrelationEngine

        if daemon:
            log.info("correlate daemonizing log_file=%s", log_file)
            _utils._daemonize()

        engine = CorrelationEngine()

        if log_file:
            path = Path(log_file)
            if not path.exists():
                console.print(f"[red]Log file not found: {log_file}[/]")
                raise typer.Exit(1)
            engine.ingest_file(path)
        elif not sys.stdin.isatty():
            for line in sys.stdin:
                engine.ingest(line)
        else:
            console.print("[red]Provide --log-file or pipe log data via stdin.[/]")
            raise typer.Exit(1)

        traversals = engine.traversals(min_deckies)

        if output == "json":
            console.print_json(_json.dumps(engine.report_json(min_deckies), indent=2))
        elif output == "syslog":
            for line in engine.traversal_syslog_lines(min_deckies):
                typer.echo(line)
        else:
            if not traversals:
                console.print(
                    f"[yellow]No traversals detected "
                    f"(min_deckies={min_deckies}, events_indexed={engine.events_indexed}).[/]"
                )
            else:
                console.print(engine.report_table(min_deckies))
                console.print(
                    f"[dim]Parsed {engine.lines_parsed} lines · "
                    f"indexed {engine.events_indexed} events · "
                    f"{len(engine.all_attackers())} unique IPs · "
                    f"[bold]{len(traversals)}[/] traversal(s)[/]"
                )

        if emit_syslog:
            for line in engine.traversal_syslog_lines(min_deckies):
                typer.echo(line)
