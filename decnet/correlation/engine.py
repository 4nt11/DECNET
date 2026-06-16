# SPDX-License-Identifier: AGPL-3.0-or-later
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

from decnet.correlation.graph import AttackerTraversal, MutationMarker, TraversalHop
from decnet.correlation.parser import LogEvent, parse_line
from decnet.logging.syslog_formatter import (
    SEVERITY_WARNING,
    format_rfc5424,
)
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer

log = get_logger("correlation.engine")


# Decky-name prefix reserved for DECNET's own infrastructure workers
# that log attacker IPs without representing actual decoy hops. The
# prober is the canonical example: when it fingerprints an attacker's
# externally-exposed services, it writes events with
# ``hostname=decnet-prober`` and ``target_ip=<attacker IP>``. The parser
# pulls ``target_ip`` into ``attacker_ip`` so the prober event is
# co-indexed with that attacker — but it's outbound recon from the
# master, not the attacker traversing into another decoy. Excluding the
# whole ``decnet-*`` namespace from distinct-decky counts and hop paths
# avoids labelling every fingerprinted attacker as a "traversal."
_INTERNAL_DECKY_PREFIX = "decnet-"


def _is_internal_decky(name: str) -> bool:
    """True if ``name`` is a DECNET internal worker (prober, etc.) — not a real decoy."""
    return bool(name) and name.startswith(_INTERNAL_DECKY_PREFIX)


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
        # decky_name → chronological list of mutation events.  Sibling
        # index to ``_events``; traversals() joins them by time window.
        self._mutations: dict[str, list[LogEvent]] = defaultdict(list)
        # Total lines parsed (including no-IP and non-DECNET lines)
        self.lines_parsed: int = 0
        # Total events indexed (had an attacker_ip)
        self.events_indexed: int = 0
        # Total mutation events indexed (kind="mutation")
        self.mutations_indexed: int = 0
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
        if event.kind == "mutation":
            self._mutations[event.decky].append(event)
            self.mutations_indexed += 1
            return event
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
            # Exclude internal-infrastructure events (e.g. prober) from
            # distinct-decky counting and the hop list. They aren't
            # attacker movement — they're outbound recon co-indexed by
            # attacker IP. Without this filter every fingerprinted
            # attacker shows up as a 2-decky "traversal" with a bogus
            # ``dmz-gateway → decnet-prober`` path.
            decoy_events = [e for e in events if not _is_internal_decky(e.decky)]
            if len({e.decky for e in decoy_events}) < min_deckies:
                continue
            hops = sorted(
                (TraversalHop(e.timestamp, e.decky, e.service, e.event_type)
                 for e in decoy_events),
                key=lambda h: h.timestamp,
            )
            # Per-attacker mutation markers: any mutation on a touched
            # decky between first_seen and last_seen.  Window is
            # inclusive on both ends so a creation-at-T0 + first-contact-
            # at-T0 race still attaches the marker.
            first_ts = hops[0].timestamp
            last_ts = hops[-1].timestamp
            touched = {h.decky for h in hops}
            markers: list[MutationMarker] = []
            for decky in touched:
                for mev in self._mutations.get(decky, ()):
                    if first_ts <= mev.timestamp <= last_ts:
                        markers.append(_marker_from_event(mev))
            markers.sort(key=lambda m: m.timestamp)
            result.append(AttackerTraversal(
                attacker_ip=ip, hops=hops, mutations_during=markers,
            ))
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

    # ------------------------------------------------------------------ #
    # Credential reuse                                                     #
    # ------------------------------------------------------------------ #

    async def correlate_credential_reuse(
        self,
        repo: Any,
        min_targets: int = 2,
    ) -> list[dict[str, Any]]:
        """Detect cross-target credential reuse and persist findings.

        Groups every ``Credential`` row by ``(secret_sha256, secret_kind,
        principal)``. Groups crossing *min_targets* distinct
        ``(decky, service)`` pairs are folded into ``CredentialReuse`` via
        :meth:`BaseRepository.upsert_credential_reuse` — one upsert per
        underlying credential row, since the upsert itself dedups on the
        unique key and recomputes aggregates from the credentials table.

        Returns the upsert results that flipped ``inserted`` or
        ``changed``, so the caller can publish ``credential.reuse.detected``
        for each new or grown finding without re-querying.
        """
        results: list[dict[str, Any]] = []
        candidates = await repo.find_credential_reuse_candidates(min_targets)
        for group in candidates:
            # Per-group flags: each credential in a group hits the same
            # CredentialReuse row, so several upserts may flip
            # ``inserted``/``changed`` along the way. Collapse to one
            # publish per group keyed by the final state — otherwise a
            # group of N creds emits N partial reuse.detected events
            # with intermediate target_counts.
            final_row: dict[str, Any] | None = None
            saw_insert = False
            saw_change = False
            for cred in group["credentials"]:
                row = await repo.upsert_credential_reuse(
                    secret_sha256=group["secret_sha256"],
                    secret_kind=group["secret_kind"],
                    principal=group["principal"],
                    attacker_uuid=cred.get("attacker_uuid"),
                    attacker_ip=cred["attacker_ip"],
                    decky=cred["decky_name"],
                    service=cred["service"],
                    attempt_count=int(cred.get("attempt_count") or 1),
                )
                if row is None:
                    continue
                final_row = row
                saw_insert = saw_insert or bool(row.get("inserted"))
                saw_change = saw_change or bool(row.get("changed"))
            if final_row is not None and (saw_insert or saw_change):
                final_row["inserted"] = saw_insert
                final_row["changed"] = saw_change
                results.append(final_row)
        return results

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

def _marker_from_event(event: LogEvent) -> MutationMarker:
    """Build a :class:`MutationMarker` from a parsed ``decky_mutated`` log event.

    The mutator emits ``old_services``/``new_services`` as comma-joined
    strings in the SD params (the RFC 5424 grammar doesn't have native
    lists).  We split them back on the way out — empty string ⇒ empty
    list, matching the creation/retirement emission sites.
    """
    def _split(s: str) -> list[str]:
        return [p for p in s.split(",") if p]

    return MutationMarker(
        timestamp=event.timestamp,
        decky=event.decky,
        old_services=_split(event.fields.get("old_services", "")),
        new_services=_split(event.fields.get("new_services", "")),
        trigger=event.fields.get("trigger", ""),
    )


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"
