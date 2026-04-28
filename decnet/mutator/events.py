"""Mutation-event emission.

One helper (:func:`emit_decky_mutated`) writes every substrate
transition to two places at once:

1. **RFC 5424 syslog** — appended to the collector's ingest log, so
   the correlation engine picks the event up alongside attacker
   events and can interleave substrate-change markers into traversals.
2. **Bus topic** ``decky.<name>.mutation`` — fire-and-forget
   notification for live UI consumers (SSE, dashboards).

The split mirrors the DB-vs-bus contract: syslog is durable, bus is
at-most-once.  Either path failing must never crash the mutator loop,
so both sides are wrapped in broad ``try/except log.warning``.
"""
from __future__ import annotations

import socket as _socket
from pathlib import Path
from typing import Any, Literal

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.publish import publish_safely as _publish_safely
from decnet.env import DECNET_INGEST_LOG_FILE
from decnet.logging import get_logger
from decnet.logging.syslog_formatter import format_rfc5424

log = get_logger("mutator.events")


# Trigger enum — wide on purpose so the schema stays stable as v2/v3
# features (behavioral + federation) land.  Every call site supplies
# exactly one of these.
MutationTrigger = Literal[
    "creation",     # initial deploy of a decky
    "retirement",   # teardown / removal
    "scheduled",    # mutator watch-loop interval tick
    "operator",     # explicit force via API/CLI/UI
    "behavioral",   # future: attacker-behavior-driven rotation
    "healer",       # future: re-apply by the healer worker
    "federation",   # future: cross-operator MazeNET mutation
]

_EVENT_TYPE = "decky_mutated"
_MUTATOR_APP = "mutator"
_MUTATOR_HOSTNAME = _socket.gethostname()


async def emit_decky_mutated(
    bus: BaseBus | None,
    *,
    decky: str,
    old_services: list[str],
    new_services: list[str],
    trigger: MutationTrigger,
    actor: str | None = None,
    log_path: Path | str | None = None,
) -> None:
    """Emit one ``decky_mutated`` event on both the syslog stream and the bus.

    *log_path* defaults to :data:`decnet.env.DECNET_INGEST_LOG_FILE`.
    Pass an explicit path (or ``None``) in tests to redirect or suppress
    the file write.  A missing parent directory is a soft failure —
    logged once and skipped — because the correlator works without
    mutation events and we'd rather degrade than crash.
    """
    fields: dict[str, Any] = {
        "decky": decky,
        "old_services": ",".join(old_services),
        "new_services": ",".join(new_services),
        "trigger": trigger,
    }
    if actor:
        fields["actor"] = actor

    # ── Syslog side ───────────────────────────────────────────────
    target = Path(log_path) if log_path is not None else Path(DECNET_INGEST_LOG_FILE)
    try:
        line = format_rfc5424(
            service=_MUTATOR_APP,
            hostname=decky,  # per-decky HOSTNAME so correlator indexes it correctly
            event_type=_EVENT_TYPE,
            **fields,
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
    except Exception as exc:  # noqa: BLE001
        log.warning("syslog emission failed decky=%s path=%s: %s",
                    decky, target, exc)

    # ── Bus side ──────────────────────────────────────────────────
    payload: dict[str, Any] = {
        "decky": decky,
        "old_services": list(old_services),
        "new_services": list(new_services),
        "trigger": trigger,
    }
    if actor:
        payload["actor"] = actor
    await _publish_safely(
        bus,
        _topics.decky_mutation(decky),
        payload,
        event_type=_topics.DECKY_MUTATION,
    )
