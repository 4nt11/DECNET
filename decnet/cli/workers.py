# SPDX-License-Identifier: AGPL-3.0-or-later
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

    @app.command(name="enrich")
    def enrich(
        poll_interval_secs: float = typer.Option(
            60.0, "--poll-interval", "-i",
            help="Slow-tick fallback when the bus is idle or unavailable (seconds)",
        ),
        ttl_hours: int = typer.Option(
            24, "--ttl-hours",
            help="Cache lifetime per attacker IP — re-firings inside the window short-circuit before any HTTP egress",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Threat-intel enrichment worker — fan out per attacker IP across
        configured providers (GreyNoise, AbuseIPDB, abuse.ch Feodo Tracker
        + ThreatFox), cache the verdict in ``attacker_intel``, and publish
        ``attacker.intel.enriched`` for SIEM-bound webhook consumers.
        """
        import asyncio
        from decnet.intel.worker import run_intel_loop
        from decnet.web.dependencies import repo

        if daemon:
            log.info(
                "enrich daemonizing poll=%s ttl_hours=%d",
                poll_interval_secs, ttl_hours,
            )
            _utils._daemonize()

        log.info(
            "enrich command invoked poll=%s ttl_hours=%d",
            poll_interval_secs, ttl_hours,
        )
        console.print(
            f"[bold cyan]Intel enrichment starting[/] "
            f"poll={poll_interval_secs}s ttl={ttl_hours}h"
        )
        console.print("[dim]Press Ctrl+C to stop[/]")

        async def _run() -> None:
            await repo.initialize()
            await run_intel_loop(
                repo,
                poll_interval_secs=poll_interval_secs,
                ttl_hours=ttl_hours,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Intel enrichment stopped.[/]")

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

    @app.command(name="attribution")
    def attribution(
        multi_actor_tick_secs: float = typer.Option(
            60.0, "--multi-actor-tick", "-t",
            help=(
                "Cross-primitive multi_actor correlator tick interval (seconds). "
                "Walks attribution_state for identities flagged on >= 2 "
                "primitives and emits attribution.profile.multi_actor_suspected."
            ),
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Attribution engine v0 — per-(identity, primitive) state machine.

        Subscribes to ``attacker.observation.>`` and, for each event,
        ensures a stub identity row, runs the merger over the full
        per-(identity, primitive) observation series, upserts the
        derived state, and publishes
        ``attribution.profile.state_changed`` only on transition.
        Periodic tick fires
        ``attribution.profile.multi_actor_suspected`` when >= 2
        primitives flag the same identity.

        Closes DEBT-051. Bright-line scope: behavioural coherence and
        drift only — never persona attribution to natural persons.
        """
        import asyncio
        from decnet.correlation.attribution_worker import (
            run_attribution_loop,
        )
        from decnet.web.dependencies import repo

        if daemon:
            log.info(
                "attribution worker daemonizing tick=%s",
                multi_actor_tick_secs,
            )
            _utils._daemonize()

        log.info(
            "attribution worker command invoked tick=%s",
            multi_actor_tick_secs,
        )
        console.print(
            f"[bold cyan]Attribution engine starting[/] "
            f"multi_actor_tick={multi_actor_tick_secs}s"
        )
        console.print("[dim]Press Ctrl+C to stop[/]")

        async def _run() -> None:
            await repo.initialize()
            await run_attribution_loop(
                repo,
                multi_actor_tick_secs=multi_actor_tick_secs,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Attribution engine stopped.[/]")

    @app.command(name="clusterer")
    def clusterer(
        poll_interval_secs: float = typer.Option(
            60.0, "--poll-interval", "-i",
            help="Slow-tick fallback when the bus is idle or unavailable (seconds)",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Identity-resolution clusterer.

        Bus-woken on ``attacker.observed`` and ``attacker.scored``;
        builds a similarity graph over observations, runs
        connected-components, writes ``attacker_identities`` rows, and
        publishes ``identity.formed`` / ``identity.observation.linked``
        / ``identity.merged`` / ``identity.unmerged``.
        """
        import asyncio
        from decnet.cli.gating import _require_master_mode
        from decnet.clustering.worker import run_clusterer_loop
        from decnet.web.dependencies import repo

        _require_master_mode("clusterer")

        if daemon:
            log.info("clusterer daemonizing poll=%s", poll_interval_secs)
            _utils._daemonize()

        log.info("clusterer command invoked poll=%s", poll_interval_secs)
        console.print(
            f"[bold cyan]Identity clusterer starting[/] "
            f"poll={poll_interval_secs}s"
        )
        console.print("[dim]Press Ctrl+C to stop[/]")

        async def _run() -> None:
            await repo.initialize()
            await run_clusterer_loop(
                repo, poll_interval_secs=poll_interval_secs,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Identity clusterer stopped.[/]")

    @app.command(name="campaign-clusterer")
    def campaign_clusterer(
        poll_interval_secs: float = typer.Option(
            60.0, "--poll-interval", "-i",
            help="Slow-tick fallback when the bus is idle or unavailable (seconds)",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """Campaign clusterer — groups identities into operations.

        Bus-woken on ``identity.>`` (any identity-layer change is
        potential input); reads ``AttackerIdentity`` rows, runs
        connected-components over the campaign-level similarity graph
        (phase-handoff / shared-infra / temporal-overlap / cohort),
        writes ``campaigns`` rows + sets ``attacker_identities.campaign_id``,
        and publishes ``campaign.formed`` / ``campaign.identity.assigned``
        / ``campaign.merged`` / ``campaign.unmerged`` plus the cross-family
        ``identity.campaign.assigned`` so identity-side subscribers see
        the badge update.
        """
        import asyncio
        from decnet.cli.gating import _require_master_mode
        from decnet.clustering.campaign.worker import (
            run_campaign_clusterer_loop,
        )
        from decnet.web.dependencies import repo

        _require_master_mode("campaign-clusterer")

        if daemon:
            log.info("campaign-clusterer daemonizing poll=%s", poll_interval_secs)
            _utils._daemonize()

        log.info(
            "campaign-clusterer command invoked poll=%s", poll_interval_secs,
        )
        console.print(
            f"[bold cyan]Campaign clusterer starting[/] "
            f"poll={poll_interval_secs}s"
        )
        console.print("[dim]Press Ctrl+C to stop[/]")

        async def _run() -> None:
            await repo.initialize()
            await run_campaign_clusterer_loop(
                repo, poll_interval_secs=poll_interval_secs,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Campaign clusterer stopped.[/]")

    # ``decnet ttp`` and ``decnet ttp-backfill`` moved to
    # :mod:`decnet.cli.ttp` — the TTP CLI surface (worker + admin verbs)
    # is colocated there, mirroring the per-feature CLI split used by
    # :mod:`decnet.cli.canary`, :mod:`decnet.cli.webhook`, etc. The
    # ``decnet-ttp.service`` systemd unit's ExecStart still resolves to
    # ``decnet ttp`` because the command name is unchanged.
