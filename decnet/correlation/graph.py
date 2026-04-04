"""
Traversal graph data types for the DECNET correlation engine.

An AttackerTraversal represents one attacker IP's movement across multiple
deckies. Hops are ordered chronologically; the traversal path is derived
by reading the unique decky sequence from the hop list.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class TraversalHop:
    """A single event in an attacker's traversal through the deception network."""

    timestamp: datetime
    decky: str        # decky node name (e.g. "decky-01")
    service: str      # service that logged the event (e.g. "ssh", "http")
    event_type: str   # MSGID from the log line (e.g. "login_attempt")


@dataclass
class AttackerTraversal:
    """
    All activity from a single attacker IP across two or more deckies,
    sorted in chronological order.
    """

    attacker_ip: str
    hops: list[TraversalHop]  # chronologically sorted

    @property
    def first_seen(self) -> datetime:
        return self.hops[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.hops[-1].timestamp

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def deckies(self) -> list[str]:
        """Unique deckies touched, preserving first-contact order."""
        seen: list[str] = []
        for hop in self.hops:
            if hop.decky not in seen:
                seen.append(hop.decky)
        return seen

    @property
    def decky_count(self) -> int:
        return len(set(h.decky for h in self.hops))

    @property
    def path(self) -> str:
        """Human-readable traversal path: decky-01 → decky-03 → decky-07"""
        return " → ".join(self.deckies)

    def to_dict(self) -> dict:
        return {
            "attacker_ip": self.attacker_ip,
            "decky_count": self.decky_count,
            "deckies": self.deckies,
            "path": self.path,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "hop_count": len(self.hops),
            "hops": [
                {
                    "timestamp": h.timestamp.isoformat(),
                    "decky": h.decky,
                    "service": h.service,
                    "event_type": h.event_type,
                }
                for h in self.hops
            ],
        }
