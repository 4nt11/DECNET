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

    @app.command(name="reuse-correlate")
    def reuse_correlate(
        min_targets: int = typer.Option(
            2, "--min-targets", "-m",
            help="Minimum distinct (decky, service) targets a secret must hit before a CredentialReuse row is persisted",
        ),
        poll_interval_secs: float = typer.Option(
            60.0, "--poll-interval", "-i",
            help="Slow-tick fallback when the bus is idle or unavailable (seconds)",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Long-running credential-reuse correlator.

        Watches the bus for ``credential.captured`` and ``attacker.observed``
        events, re-runs the reuse pass on each wake, and publishes
        ``credential.reuse.detected`` for every new or grown
        ``CredentialReuse`` row.
        """
        import asyncio
        from decnet.correlation.reuse_worker import run_reuse_loop
        from decnet.web.dependencies import repo

        if daemon:
            log.info(
                "reuse-correlate daemonizing min_targets=%d poll=%s",
                min_targets, poll_interval_secs,
            )
            _utils._daemonize()

        log.info(
            "reuse-correlate command invoked min_targets=%d poll=%s",
            min_targets, poll_interval_secs,
        )
        console.print(
            f"[bold cyan]Reuse correlator starting[/] "
            f"min_targets={min_targets} poll={poll_interval_secs}s"
        )
        console.print("[dim]Press Ctrl+C to stop[/]")

        async def _run() -> None:
            await repo.initialize()
            await run_reuse_loop(
                repo,
                poll_interval_secs=poll_interval_secs,
                min_targets=min_targets,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Reuse correlator stopped.[/]")
