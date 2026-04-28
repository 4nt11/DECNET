"""Classify RFC 5424 event_type strings as interaction vs. scan vs. noise.

Used by:
- The attacker detail endpoint to split services into "scanned" and
  "interacted with" buckets, distinguishing port scanners from
  attackers who actually engaged.
- The profiler worker to filter command-family events when extracting
  executed-command history.

Classification is conservative: an unknown event_type defaults to
``scan`` rather than ``interaction``. That way a new service template
emitting a fresh verb shows up as "scanned" on the dashboard — visible
but not over-credited. Adding it to ``INTERACTION_EVENT_TYPES`` is
always a deliberate promotion.
"""
from __future__ import annotations

from typing import Literal

# Events that mean the attacker did something past reconnaissance —
# executed a command, sent mail, uploaded a file, subscribed to a topic.
# A service with ≥1 of these from a given attacker is "interacted with".
INTERACTION_EVENT_TYPES: frozenset[str] = frozenset({
    # Shell / command-family — lifted from the profiler's original
    # command-extraction frozenset; this module is now the source of
    # truth for that vocabulary too.
    "command",
    "exec",
    "query",
    "input",
    "shell_input",
    "execute",
    "run",
    "sql_query",
    "redis_command",
    "ldap_search",
    # SMTP meaningful engagement — once MAIL FROM / RCPT TO lands the
    # attacker is trying to send mail, not just banner-grab.
    # message_accepted is the DATA-commit moment.
    "mail_from",
    "rcpt_to",
    "rcpt_denied",
    "message_accepted",
    # File / payload activity
    "file_captured",
    "upload",
    "download_attempt",
    "retr",  # FTP retrieve
    # Pub/sub operational use (vs. mere connection)
    "publish",
    "subscribe",
    # A recorded TTY session is always an interaction — sessrec only
    # writes when there was PTY input.
    "session_recorded",
})


# Events that are DECNET-internal or protocol-framework noise rather
# than attacker-caused signal. Dropped from both buckets.
NOISE_EVENT_TYPES: frozenset[str] = frozenset({
    "startup",
    "shutdown",
    "config_error",
    "parse_error",
    "unknown_packet",
    "unknown_opcode",
    "unknown_command",
    "protocol_error",
})


EventKind = Literal["interaction", "scan", "noise"]


def classify_event(event_type: str) -> EventKind:
    """Return the kind label for a single event_type string."""
    if event_type in INTERACTION_EVENT_TYPES:
        return "interaction"
    if event_type in NOISE_EVENT_TYPES:
        return "noise"
    return "scan"


def bucket_services(
    pairs: list[tuple[str, str]],
) -> dict[str, list[str]]:
    """Group distinct service names into scanned vs. interacted buckets.

    *pairs* is an iterable of ``(service, event_type)`` tuples — the
    shape the repo returns from a ``SELECT DISTINCT service, event_type``
    query. A service is placed in ``interacted`` if any of its events
    classifies as interaction; otherwise in ``scanned`` if any event
    classifies as scan; noise-only services are dropped.

    Return shape: ``{"interacted": [...sorted...], "scanned": [...sorted...]}``.
    Buckets are disjoint by construction.
    """
    best: dict[str, EventKind] = {}
    for service, event_type in pairs:
        kind = classify_event(event_type)
        current = best.get(service)
        # Rank: interaction > scan > noise > unset.
        if current == "interaction":
            continue
        if kind == "interaction":
            best[service] = "interaction"
        elif kind == "scan" and current != "interaction":
            best[service] = "scan"
        elif kind == "noise" and current is None:
            best[service] = "noise"
    interacted = sorted(s for s, k in best.items() if k == "interaction")
    scanned = sorted(s for s, k in best.items() if k == "scan")
    return {"interacted": interacted, "scanned": scanned}
