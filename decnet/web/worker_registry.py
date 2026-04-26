"""In-process registry that aggregates worker heartbeats from the bus.

The API process subscribes to ``system.*.health`` (plus the bare
``system.bus.health`` leaf that the bus daemon itself publishes) at
lifespan startup and keeps a simple last-seen dict.  The
:func:`snapshot` call renders that into a stable list of known workers,
including those we have **never** heard from (surfaced as ``unknown`` —
which is distinct from ``stale``, a worker that used to pulse but went
silent).

Names are the canonical singular forms used by the CLI table in
``CLAUDE.md``.  Keeping the list hardcoded is deliberate: an unknown
topic segment would otherwise let any publisher inject a row into the
Workers panel.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.logging import get_logger
from decnet.web.db.models import WorkerStatus

log = get_logger("web.worker_registry")

# Canonical worker names.  Mirrors the CLAUDE.md worker table; keep in
# sync when a new worker CLI lands.  The API process is included because
# it self-publishes its own heartbeat so the panel has at least one
# always-on row to ground "bus is reachable" sanity.
KNOWN_WORKERS: tuple[str, ...] = (
    "api",
    "bus",
    "collector",
    "profiler",   # hosts the correlation engine too — no separate daemon
    "sniffer",
    "prober",
    "mutator",
    "reuse-correlator",  # credential-reuse pass — bus-woken on credential.captured
    "enrich",     # threat-intel enrichment — bus-woken on attacker.observed/scored
    "webhook",    # external SIEM/SOAR egress — bus consumer → HMAC HTTP POSTs
    "agent",
    "forwarder",
    "updater",
)

# ``ok`` window: 3× the 30s heartbeat interval in
# :func:`decnet.bus.publish.run_health_heartbeat`.  One missed beat is
# noise; three missed beats is a worker problem.
OK_WINDOW_SECONDS = 90.0


class WorkerRegistry:
    """Last-seen aggregator for worker heartbeats.

    Single-writer (the subscriber task) + many-reader (HTTP requests).
    Python's GIL makes the dict mutations atomic enough that we don't
    need a lock for the read path; ``snapshot`` copies the dict under a
    single reference so a concurrent write can't produce a torn view.
    """

    def __init__(self) -> None:
        # name → {"ts": float, "payload": dict}
        self._seen: Dict[str, Dict[str, Any]] = {}
        self._task: asyncio.Task[None] | None = None

    def record(self, worker: str, ts: float, payload: Dict[str, Any]) -> None:
        self._seen[worker] = {"ts": ts, "payload": payload}

    def snapshot(self) -> List[WorkerStatus]:
        now = time.time()
        seen = dict(self._seen)  # point-in-time copy
        out: List[WorkerStatus] = []
        for name in KNOWN_WORKERS:
            entry = seen.get(name)
            if entry is None:
                out.append(WorkerStatus(
                    name=name,
                    status="unknown",
                    last_heartbeat_ts=None,
                    seconds_since=None,
                    extra={},
                ))
                continue
            ts = float(entry["ts"])
            seconds_since = max(0.0, now - ts)
            status = "ok" if seconds_since < OK_WINDOW_SECONDS else "stale"
            payload = dict(entry.get("payload") or {})
            # ``worker`` and ``ts`` are redundant with the row itself;
            # strip them so ``extra`` only surfaces worker-contributed
            # metadata (uptime, queue depth, etc.).
            payload.pop("worker", None)
            payload.pop("ts", None)
            out.append(WorkerStatus(
                name=name,
                status=status,  # type: ignore[arg-type]
                last_heartbeat_ts=ts,
                seconds_since=seconds_since,
                extra=payload,
            ))
        return out

    async def start(self, bus: BaseBus | None) -> None:
        """Begin subscribing.  Idempotent; a second call is a no-op."""
        if self._task is not None and not self._task.done():
            return
        if bus is None:
            log.debug("worker registry: no bus — panel will show all UNKNOWN")
            return
        self._task = asyncio.create_task(self._run(bus))

    async def stop(self) -> None:
        """Cancel the subscriber task.  Idempotent."""
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        self._task = None

    async def _run(self, bus: BaseBus) -> None:
        """Fan in both ``system.*.health`` and ``system.bus.health``.

        Two subscriptions because the bus's own heartbeat uses the
        pre-existing ``system.bus.health`` string (not nested under
        ``system.<worker>.health``) and ``*`` matches exactly one token,
        so the wildcard would miss it.
        """
        worker_sub = bus.subscribe("system.*.health")
        bus_sub = bus.subscribe(_topics.system("bus.health"))
        try:
            async with worker_sub, bus_sub:
                async for event in _merge(worker_sub, bus_sub):
                    self._on_event(event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("worker registry subscriber exited: %s", exc)

    def _on_event(self, event: Any) -> None:
        payload = event.payload or {}
        # ``system.<name>.health`` — middle token is the worker name.
        # ``system.bus.health`` — special case, derive from topic.
        tokens = event.topic.split(".")
        name: str | None = None
        if len(tokens) == 3 and tokens[0] == "system" and tokens[2] == "health":
            # tokens[1] is the worker name; also handles "bus" when the
            # bus daemon publishes ``system.bus.health``.
            name = tokens[1]
        if not name:
            return
        if name not in KNOWN_WORKERS:
            # Unknown worker name — log once at debug; don't widen the
            # panel beyond the hardcoded list.
            log.debug("heartbeat from unknown worker=%r", name)
            return
        ts = float(payload.get("ts", time.time()))
        self.record(name, ts, payload)


async def _merge(*subs: Any):
    """Round-robin over multiple subscriptions without losing events.

    asyncio.wait + FIRST_COMPLETED keeps both streams live; a plain
    ``async for`` over a merged generator would serialise them.
    """
    iters = [sub.__aiter__() for sub in subs]
    pending = {asyncio.create_task(it.__anext__()): it for it in iters}
    try:
        while pending:
            done, _ = await asyncio.wait(
                pending.keys(), return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                it = pending.pop(task)
                try:
                    yield task.result()
                except StopAsyncIteration:
                    continue
                pending[asyncio.create_task(it.__anext__())] = it
    finally:
        for task in pending:
            task.cancel()


# Module-level singleton so the API lifespan and route handlers share
# one registry without threading it through every Depends.
_registry: WorkerRegistry | None = None


def get_registry() -> WorkerRegistry:
    global _registry
    if _registry is None:
        _registry = WorkerRegistry()
    return _registry


def reset_registry_for_tests() -> None:
    """Drop the singleton — tests that spin up their own registry."""
    global _registry
    _registry = None
