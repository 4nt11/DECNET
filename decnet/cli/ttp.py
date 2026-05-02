"""``decnet ttp`` — TTP-tagging worker and admin commands.

Two flat commands share this module:

* ``decnet ttp`` — runs the long-running tagger worker. Bus-woken on
  ``attacker.session.ended`` / ``attacker.observed`` /
  ``attacker.intel.enriched`` / ``identity.{formed,merged}`` /
  ``credential.reuse.detected`` / ``email.received`` / ``canary.>``;
  dispatches each event through :class:`CompositeTagger` (RuleEngine +
  Behavioral / Intel / CanaryFingerprint / Email / Identity / Credential
  lifters), persists ``ttp_tag`` rows via the idempotent
  ``INSERT OR IGNORE`` write, and publishes ``ttp.tagged`` +
  ``ttp.rule.fired.<technique_id>`` only when the insert returned a
  non-zero rowcount (loop-prevention invariant from TTP_TAGGING.md
  §"Bus topics"). Invoked by the ``decnet-ttp.service`` systemd unit
  so its argv must stay stable.

* ``decnet ttp-backfill`` — replays historical events (shell commands
  recorded on :class:`Attacker.commands`, :class:`CanaryTrigger` rows)
  through the live tagger. Writes ``ttp_tag`` rows using the same
  idempotent insert path. **Does not publish** to the bus — replay must
  not re-trigger SIEM/webhook fan-out on already-attributed events.

Both are master-only — gated via ``MASTER_ONLY_COMMANDS`` in
:mod:`decnet.cli.gating`.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import typer

from decnet.ttp.factory import CompositeTagger, get_tagger

from . import utils as _utils
from .utils import console, log


_BACKFILL_SOURCES = ("command", "canary", "all")


def register(app: typer.Typer) -> None:
    @app.command(name="ttp")
    def ttp(
        poll_interval_secs: float = typer.Option(
            60.0, "--poll-interval", "-i",
            help="Slow-tick fallback when the bus is idle or unavailable (seconds)",
        ),
        daemon: bool = typer.Option(
            False, "--daemon", "-d",
            help="Detach to background as a daemon process",
        ),
    ) -> None:
        """TTP-tagging worker — MITRE ATT&CK technique tagging."""
        from decnet.cli.gating import _require_master_mode
        from decnet.ttp.worker import run_ttp_worker_loop
        from decnet.web.dependencies import repo

        _require_master_mode("ttp")

        if daemon:
            log.info("ttp daemonizing poll=%s", poll_interval_secs)
            _utils._daemonize()

        log.info("ttp command invoked poll=%s", poll_interval_secs)
        console.print(
            f"[bold cyan]TTP tagging worker starting[/] "
            f"poll={poll_interval_secs}s"
        )
        console.print("[dim]Press Ctrl+C to stop[/]")

        async def _run() -> None:
            await repo.initialize()
            await run_ttp_worker_loop(
                repo, poll_interval_secs=poll_interval_secs,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]TTP tagging worker stopped.[/]")

    @app.command(name="ttp-backfill")
    def ttp_backfill(
        since_days: int = typer.Option(
            7, "--since-days", "-s",
            min=1, max=3650,
            help="Replay events whose source row is newer than N days ago.",
        ),
        source: str = typer.Option(
            "all", "--source",
            help=f"Source slice to replay. One of: {', '.join(_BACKFILL_SOURCES)}.",
        ),
        dry_run: bool = typer.Option(
            False, "--dry-run",
            help="Run the tagger but skip insert_tags. Reports counts only.",
        ),
        batch_size: int = typer.Option(
            500, "--batch-size",
            min=1, max=100_000,
            help="Number of tags accumulated before each repo.insert_tags call.",
        ),
    ) -> None:
        """Replay historical attacker activity through the live tagger.

        Walks ``Attacker.commands`` (per-IP shell-command history) and
        ``CanaryTrigger`` (canary callback log) since N days ago,
        builds the same :class:`TaggerEvent` shape the live worker
        emits, and persists tags via the idempotent INSERT OR IGNORE
        write. Re-running is safe — a second pass over identical
        source rows reports ``inserted=0``.

        Bus publish is intentionally suppressed; SIEM / webhook fan-out
        sees only live events, never replays.
        """
        from decnet.cli.gating import _require_master_mode
        from decnet.web.dependencies import repo

        _require_master_mode("ttp-backfill")

        if source not in _BACKFILL_SOURCES:
            console.print(
                f"[red]invalid --source {source!r}; expected one of "
                f"{_BACKFILL_SOURCES}[/]"
            )
            raise typer.Exit(code=2)

        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=since_days)
        console.print(
            f"[bold cyan]TTP backfill[/] since={cutoff.isoformat()} "
            f"source={source} dry_run={dry_run} batch_size={batch_size}"
        )

        async def _run() -> None:
            await repo.initialize()
            await _backfill(
                repo,
                cutoff=cutoff,
                sources=_resolve_sources(source),
                dry_run=dry_run,
                batch_size=batch_size,
            )

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Backfill interrupted.[/]")


def _resolve_sources(name: str) -> tuple[str, ...]:
    if name == "all":
        return ("command", "canary")
    return (name,)


async def _backfill(
    repo: Any,
    *,
    cutoff: datetime,
    sources: tuple[str, ...],
    dry_run: bool,
    batch_size: int,
) -> None:
    """Drive the per-source backfill loops and report structured counts.

    One :class:`CompositeTagger` is built once and reused for every
    source — the per-lifter watch fan-out the live worker performs is
    inlined here as a `watch_store()` startup task per
    :class:`WatchableTagger`, so the dispatch indexes hydrate before
    we start feeding events.
    """
    # Import-time bound so tests can monkeypatch ``decnet.cli.ttp.get_tagger``
    # to inject a recording fake without touching the global factory.
    tagger = get_tagger()
    watch_tasks: list[asyncio.Task[None]] = []
    if isinstance(tagger, CompositeTagger):
        for watchable in tagger.iter_watchables():
            watch_tasks.append(asyncio.create_task(watchable.watch_store()))
    # Yield once so each watch_store gets a chance to run its
    # initial `load_compiled` before we feed the first event.
    await asyncio.sleep(0.05)

    try:
        if "command" in sources:
            await _backfill_commands(
                repo, tagger, cutoff=cutoff,
                dry_run=dry_run, batch_size=batch_size,
            )
        if "canary" in sources:
            await _backfill_canaries(
                repo, tagger, cutoff=cutoff,
                dry_run=dry_run, batch_size=batch_size,
            )
    finally:
        for task in watch_tasks:
            task.cancel()
        for task in watch_tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


async def _backfill_commands(
    repo: Any,
    tagger: Any,
    *,
    cutoff: datetime,
    dry_run: bool,
    batch_size: int,
) -> None:
    from decnet.ttp.base import TaggerEvent

    started = time.monotonic()
    rows_seen = 0
    cmds_seen = 0
    inserted = 0
    pending: list[Any] = []

    async for attacker, commands in repo.iter_attacker_commands_since(cutoff):
        rows_seen += 1
        for idx, cmd in enumerate(commands):
            cmds_seen += 1
            text = cmd.get("command_text") or cmd.get("text")
            if not isinstance(text, str):
                continue
            cmd_id = (
                cmd.get("id")
                or cmd.get("uuid")
                or cmd.get("command_id")
                or f"{attacker.uuid}#cmd{idx}"
            )
            event = TaggerEvent(
                source_kind="command",
                source_id=str(cmd_id),
                attacker_uuid=attacker.uuid,
                identity_uuid=getattr(attacker, "identity_id", None),
                session_id=cmd.get("session_id"),
                decky_id=cmd.get("decky_id") or cmd.get("decky"),
                payload={**cmd, "command_text": text},
            )
            tags = await tagger.tag(event)
            if tags:
                pending.extend(tags)
            if len(pending) >= batch_size:
                inserted += await _flush(repo, pending, dry_run)
                pending = []
    if pending:
        inserted += await _flush(repo, pending, dry_run)
    elapsed = time.monotonic() - started
    console.print(
        f"source=command rows={rows_seen} commands={cmds_seen} "
        f"inserted={inserted} dry_run={dry_run} elapsed_s={elapsed:.2f}"
    )


async def _backfill_canaries(
    repo: Any,
    tagger: Any,
    *,
    cutoff: datetime,
    dry_run: bool,
    batch_size: int,
) -> None:
    from decnet.ttp.base import TaggerEvent

    started = time.monotonic()
    rows_seen = 0
    inserted = 0
    pending: list[Any] = []

    async for trigger in repo.iter_canary_triggers_since(cutoff):
        rows_seen += 1
        event = TaggerEvent(
            source_kind="canary_fingerprint",
            source_id=trigger.uuid,
            attacker_uuid=trigger.attacker_id,
            identity_uuid=None,
            session_id=None,
            decky_id=None,
            payload={
                "token_uuid": trigger.token_uuid,
                "src_ip": trigger.src_ip,
                "ua_signature": trigger.user_agent or "",
                "user_agent": trigger.user_agent,
                "request_path": trigger.request_path,
                "dns_qname": trigger.dns_qname,
                "headers": trigger.headers(),
            },
        )
        tags = await tagger.tag(event)
        if tags:
            pending.extend(tags)
        if len(pending) >= batch_size:
            inserted += await _flush(repo, pending, dry_run)
            pending = []
    if pending:
        inserted += await _flush(repo, pending, dry_run)
    elapsed = time.monotonic() - started
    console.print(
        f"source=canary rows={rows_seen} inserted={inserted} "
        f"dry_run={dry_run} elapsed_s={elapsed:.2f}"
    )


async def _flush(repo: Any, tags: list[Any], dry_run: bool) -> int:
    if dry_run:
        return 0
    return int(await repo.insert_tags(tags))
