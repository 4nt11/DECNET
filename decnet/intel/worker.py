"""Long-running threat-intel enrichment worker.

Fans out per attacker IP across the configured intel providers
(GreyNoise / AbuseIPDB / abuse.ch Feodo + ThreatFox), writes the
combined verdict to ``attacker_intel``, and publishes
``attacker.intel.enriched`` for downstream consumers (SIEM webhooks,
dashboard).

Mirrors :mod:`decnet.correlation.reuse_worker` — bus-woken on
``attacker.scored`` and ``attacker.observed`` for sub-second latency,
falls back to a slow tick (default 60s) when the bus is unavailable so
operators with bus disabled still get periodic backfills.

A single worker instance handles all providers; provider-level
concurrency is bounded by the per-provider semaphore on each
:class:`~decnet.intel.base.IntelProvider`. The worker itself does not
hold a global lock — each IP runs through its providers concurrently.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely,
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.intel.base import IntelProvider, IntelResult
from decnet.intel.factory import get_intel_providers
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("intel.worker")

_DEFAULT_POLL_SECS = 60.0
_DEFAULT_TTL_HOURS = 24
_BACKFILL_BATCH = 50

# Aggregate-verdict precedence: most-confident first. Any provider
# returning the higher tier wins regardless of how many lower-tier
# verdicts exist alongside it.
_VERDICT_PRECEDENCE = ("malicious", "suspicious", "benign", "unknown")


def _aggregate(verdicts: list[Optional[str]]) -> Optional[str]:
    """Pick the strongest provider verdict, or ``None`` if all silent."""
    seen = {v for v in verdicts if v}
    if not seen:
        return None
    for tier in _VERDICT_PRECEDENCE:
        if tier in seen:
            return tier
    return None


def _build_intel_event_payload(
    attacker_uuid: str,
    ip: str,
    row: dict[str, Any],
    providers: list[IntelProvider],
) -> dict[str, Any]:
    """Project the AttackerIntel row into the bus event the TTP worker
    consumes as ``source_kind="intel"``.
    """
    return {
        "attacker_uuid": attacker_uuid,
        "attacker_ip": ip,
        "aggregate_verdict": row.get("aggregate_verdict"),
        "providers": [p.name for p in providers],
        # AbuseIPDB
        "abuseipdb_score": row.get("abuseipdb_score"),
        "abuseipdb_categories": row.get("abuseipdb_categories") or [],
        # GreyNoise
        "greynoise_classification": row.get("greynoise_classification"),
        "greynoise_name": row.get("greynoise_name"),
        "greynoise_tags": row.get("greynoise_tags") or [],
        # Feodo
        "feodo_listed": row.get("feodo_listed"),
        "feodo_malware_family": row.get("feodo_malware_family"),
        # ThreatFox
        "threatfox_listed": row.get("threatfox_listed"),
        "threatfox_threat_types": row.get("threatfox_threat_types") or [],
        "threatfox_ioc_types": row.get("threatfox_ioc_types") or [],
        "threatfox_malware_families": row.get("threatfox_malware_families") or [],
    }


async def _enrich_one(
    attacker_uuid: str,
    ip: str,
    providers: list[IntelProvider],
    ttl_hours: int,
) -> dict[str, Any]:
    """Fan out across providers for a single attacker and assemble the row.

    Keyed on ``attacker_uuid`` for the eventual upsert; the IP is the wire
    value the providers see and is denormalised onto the row for SIEM /
    audit consumers.
    """
    results: list[IntelResult] = await asyncio.gather(
        *(p.lookup(ip) for p in providers),
        return_exceptions=False,  # providers contractually never raise
    )

    now = datetime.now(timezone.utc)
    row: dict[str, Any] = {
        "attacker_uuid": attacker_uuid,
        "attacker_ip": ip,
        "cached_at": now,
        "expires_at": now + timedelta(hours=ttl_hours),
    }
    verdicts: list[Optional[str]] = []
    for result in results:
        if result.error:
            log.warning(
                "intel: provider %s failed for ip=%s: %s",
                result.provider, ip, result.error,
            )
            continue
        row.update(result.column_updates)
        verdicts.append(result.verdict)
    row["aggregate_verdict"] = _aggregate(verdicts)
    return row


async def run_intel_loop(
    repo: BaseRepository,
    *,
    poll_interval_secs: float = _DEFAULT_POLL_SECS,
    ttl_hours: int = _DEFAULT_TTL_HOURS,
    backfill_batch: int = _BACKFILL_BATCH,
    providers: Optional[list[IntelProvider]] = None,
    shutdown: Optional[asyncio.Event] = None,
) -> None:
    """Run the intel-enrichment loop until cancelled.

    *providers* defaults to :func:`get_intel_providers` — tests pass a
    list of fakes. *shutdown* is an optional external stop signal; the
    loop also exits cleanly on ``CancelledError`` and ``KeyboardInterrupt``.
    """
    if providers is None:
        providers = get_intel_providers()
    log.info(
        "intel worker started providers=%s poll=%ss ttl=%sh",
        [p.name for p in providers], poll_interval_secs, ttl_hours,
    )

    bus: Optional[BaseBus] = None
    wake = asyncio.Event()
    wake_tasks: list[asyncio.Task] = []
    heartbeat_task: Optional[asyncio.Task] = None
    try:
        candidate = get_bus(client_name="enrich")
        await candidate.connect()
        bus = candidate
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, _topics.attacker(_topics.ATTACKER_OBSERVED)),
        ))
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, _topics.attacker(_topics.ATTACKER_SCORED)),
        ))
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, "enrich"),
        )
        wake_tasks.append(asyncio.create_task(
            _run_control_listener_signal(bus, "enrich"),
        ))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "intel worker: bus unavailable, running in poll-only mode: %s",
            exc,
        )

    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        while not shutdown.is_set():
            try:
                pending = await repo.get_unenriched_attackers(
                    limit=backfill_batch,
                )
            except Exception:  # noqa: BLE001
                log.exception("intel worker: backfill query failed")
                pending = []

            if pending and providers:
                for entry in pending:
                    if shutdown.is_set():
                        break
                    attacker_uuid = entry["uuid"]
                    ip = entry["ip"]
                    try:
                        row = await _enrich_one(
                            attacker_uuid, ip, providers, ttl_hours,
                        )
                        await repo.upsert_attacker_intel(row)
                        await publish_safely(
                            bus,
                            _topics.attacker(_topics.ATTACKER_INTEL_ENRICHED),
                            _build_intel_event_payload(
                                attacker_uuid, ip, row, providers,
                            ),
                            event_type=_topics.ATTACKER_INTEL_ENRICHED,
                        )
                    except Exception:  # noqa: BLE001
                        log.exception(
                            "intel worker: enrichment failed for uuid=%s ip=%s",
                            attacker_uuid, ip,
                        )

            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=float(poll_interval_secs),
                )
            except asyncio.TimeoutError:
                pass
            wake.clear()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("intel worker stopped")
    finally:
        for t in wake_tasks:
            t.cancel()
        if heartbeat_task is not None:
            heartbeat_task.cancel()
        for task in (*wake_tasks, heartbeat_task):
            if task is None:
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _wake_on(bus: BaseBus, wake: asyncio.Event, pattern: str) -> None:
    """Flip *wake* every time *pattern* fires on the bus.

    Survives transient subscriber errors by logging and exiting; the
    poll-interval fallback keeps the loop alive in poll-only mode.
    """
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for _event in sub:
                wake.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "intel worker: subscriber for %s died (%s); falling back to poll",
            pattern, exc,
        )


__all__ = ["run_intel_loop"]
