"""Recon → exfil phase sequencing for DECNET attacker profiles."""

from __future__ import annotations

from typing import Any

from decnet.correlation.parser import LogEvent
from decnet.telemetry import traced as _traced

# Events that signal "recon" phase (scans, probes, auth attempts).
_RECON_EVENT_TYPES: frozenset[str] = frozenset({
    "scan", "connection", "banner", "probe",
    "login_attempt", "auth", "auth_failure",
})

# Events that signal "exfil" / action-on-objective phase.
_EXFIL_EVENT_TYPES: frozenset[str] = frozenset({
    "download", "upload", "file_transfer", "data_exfil",
    "command", "exec", "query", "shell_input",
})

# Fields carrying payload byte counts (for "large payload" detection).
_PAYLOAD_SIZE_FIELDS: tuple[str, ...] = ("bytes", "size", "content_length")


@_traced("profiler.phase_sequence")
def phase_sequence(events: list[LogEvent]) -> dict[str, Any]:
    """
    Derive recon→exfil phase transition info.

    Returns:
      recon_end_ts       : ISO timestamp of last recon-class event (or None)
      exfil_start_ts     : ISO timestamp of first exfil-class event (or None)
      exfil_latency_s    : seconds between them (None if not both present)
      large_payload_count: count of events whose *fields* report a payload
                           ≥ 1 MiB (heuristic for bulk data transfer)
    """
    recon_end = None
    exfil_start = None
    large_payload_count = 0

    for e in sorted(events, key=lambda x: x.timestamp):
        if e.event_type in _RECON_EVENT_TYPES:
            recon_end = e.timestamp
        elif e.event_type in _EXFIL_EVENT_TYPES and exfil_start is None:
            exfil_start = e.timestamp

        for fname in _PAYLOAD_SIZE_FIELDS:
            raw = e.fields.get(fname)
            if raw is None:
                continue
            try:
                if int(raw) >= 1_048_576:
                    large_payload_count += 1
                    break
            except (TypeError, ValueError):
                continue

    latency: float | None = None
    if recon_end is not None and exfil_start is not None and exfil_start >= recon_end:
        latency = round((exfil_start - recon_end).total_seconds(), 3)

    return {
        "recon_end_ts": recon_end.isoformat() if recon_end else None,
        "exfil_start_ts": exfil_start.isoformat() if exfil_start else None,
        "exfil_latency_s": latency,
        "large_payload_count": large_payload_count,
    }
