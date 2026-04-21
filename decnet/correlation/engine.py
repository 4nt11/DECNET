"""
Cross-decky correlation engine.

Ingests RFC 5424 syslog lines from DECNET service containers and identifies
attackers that have touched more than one decky — indicating lateral movement
or an active sweep through the deception network.

Core concept
------------
Every log event that carries a source IP is indexed by that IP. Once ingestion
is complete, ``traversals()`` returns the subset of IPs that hit at least
``min_deckies`` distinct deckies, along with the full chronological hop list
for each one.

Usage
-----
    engine = CorrelationEngine()
    engine.ingest_file(Path("/var/log/decnet/decnet.log"))
    for t in engine.traversals():
        print(t.path, t.decky_count)
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from rich.table import Table

from decnet.correlation.graph import AttackerTraversal, TraversalHop
from decnet.correlation.parser import LogEvent, parse_line
from decnet.logging.syslog_formatter import (
    SEVERITY_WARNING,
    format_rfc5424,
)
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer

log = get_logger("correlation.engine")


# ``publish_fn(event_type, payload_dict)``.  Sync to avoid rippling
# ``async`` through every call site of :meth:`CorrelationEngine.ingest`;
# the caller wraps bus-publish via
# :func:`decnet.bus.publish.make_thread_safe_publisher`, which is safe to
# invoke from any thread including the event-loop thread.
CorrelationPublishFn = Callable[[str, dict[str, Any]], None]


class CorrelationEngine:
    def __init__(
        self,
        *,
        publish_fn: CorrelationPublishFn | None = None,
    ) -> None:
        # attacker_ip → chronological list of events (only events with an IP)
        self._events: dict[str, list[LogEvent]] = defaultdict(list)
        # Total lines parsed (including no-IP and non-DECNET lines)
        self.lines_parsed: int = 0
        # Total events indexed (had an attacker_ip)
        self.events_indexed: int = 0
        # Optional bus hook — invoked on first-sighting of an attacker IP.
        # Always fires exactly once per IP for the lifetime of the engine.
        self._publish_fn = publish_fn

    # ------------------------------------------------------------------ #
    # Ingestion                                                            #
    # ------------------------------------------------------------------ #

    def ingest(self, line: str) -> LogEvent | None:
        """
        Parse and index one log line.

        Returns the parsed LogEvent (even if it has no attacker IP), or
        None if the line is blank / not RFC 5424.
        """
        self.lines_parsed += 1
        event = parse_line(line)
        if event is None:
            return None
        if event.attacker_ip:
            first_sighting = event.attacker_ip not in self._events
            self._events[event.attacker_ip].append(event)
            self.events_indexed += 1
            if first_sighting and self._publish_fn is not None:
                try:
                    self._publish_fn(
                        "observed",
                        {
                            "attacker_ip": event.attacker_ip,
                            "decky": event.decky,
                            "service": event.service,
                            "event_type": event.event_type,
                            "first_seen": event.timestamp.isoformat(),
                        },
                    )
                except Exception as exc:
                    log.warning("correlation publish hook failed: %s", exc)
        return event

    @_traced("correlation.ingest_file")
    def ingest_file(self, path: Path) -> int:
        """
        Parse every line of *path* and index it.

        Returns the number of events that had an attacker IP.
        """
        with open(path) as fh:
            for line in fh:
                self.ingest(line)
        _tracer = _get_tracer("correlation")
        with _tracer.start_as_current_span("correlation.ingest_file.summary") as _span:
            _span.set_attribute("lines_parsed", self.lines_parsed)
            _span.set_attribute("events_indexed", self.events_indexed)
            _span.set_attribute("unique_ips", len(self._events))
        return self.events_indexed

    # ------------------------------------------------------------------ #
    # Query                                                                #
    # ------------------------------------------------------------------ #

    @_traced("correlation.traversals")
    def traversals(self, min_deckies: int = 2) -> list[AttackerTraversal]:
        """
        Return all attackers that touched at least *min_deckies* distinct
        deckies, sorted by first-seen time.
        """
        result: list[AttackerTraversal] = []
        for ip, events in self._events.items():
            if len({e.decky for e in events}) < min_deckies:
                continue
            hops = sorted(
                (TraversalHop(e.timestamp, e.decky, e.service, e.event_type)
                 for e in events),
                key=lambda h: h.timestamp,
            )
            result.append(AttackerTraversal(attacker_ip=ip, hops=hops))
        return sorted(result, key=lambda t: t.first_seen)

    def all_attackers(self) -> dict[str, int]:
        """Return {attacker_ip: event_count} for every IP seen, sorted by count desc."""
        return dict(
            sorted(
                {ip: len(evts) for ip, evts in self._events.items()}.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
        )

    # ------------------------------------------------------------------ #
    # Reporting                                                            #
    # ------------------------------------------------------------------ #

    def report_table(self, min_deckies: int = 2) -> Table:
        """Rich table showing every cross-decky traversal."""
        table = Table(
            title="[bold red]Traversal Graph — Cross-Decky Attackers[/]",
            show_lines=True,
        )
        table.add_column("Attacker IP", style="bold red")
        table.add_column("Deckies", style="cyan", justify="right")
        table.add_column("Traversal Path", style="yellow")
        table.add_column("First Seen", style="dim")
        table.add_column("Duration", justify="right")
        table.add_column("Events", justify="right")

        for t in self.traversals(min_deckies):
            dur = _fmt_duration(t.duration_seconds)
            table.add_row(
                t.attacker_ip,
                str(t.decky_count),
                t.path,
                t.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
                dur,
                str(len(t.hops)),
            )
        return table

    @_traced("correlation.report_json")
    def report_json(self, min_deckies: int = 2) -> dict:
        """Serialisable dict representation of all traversals."""
        return {
            "stats": {
                "lines_parsed": self.lines_parsed,
                "events_indexed": self.events_indexed,
                "unique_ips": len(self._events),
                "traversals": len(self.traversals(min_deckies)),
            },
            "traversals": [t.to_dict() for t in self.traversals(min_deckies)],
        }

    @_traced("correlation.traversal_syslog_lines")
    def traversal_syslog_lines(self, min_deckies: int = 2) -> list[str]:
        """
        Emit one RFC 5424 syslog line per detected traversal.

        Useful for forwarding correlation findings back to the SIEM alongside
        the raw service events.
        """
        lines: list[str] = []
        for t in self.traversals(min_deckies):
            line = format_rfc5424(
                service="correlator",
                hostname="decnet-correlator",
                event_type="traversal_detected",
                severity=SEVERITY_WARNING,
                attacker_ip=t.attacker_ip,
                decky_count=str(t.decky_count),
                deckies=",".join(t.deckies),
                first_seen=t.first_seen.isoformat(),
                last_seen=t.last_seen.isoformat(),
                hop_count=str(len(t.hops)),
                duration_s=str(int(t.duration_seconds)),
            )
            lines.append(line)
        return lines


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"
