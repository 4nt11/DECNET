# SPDX-License-Identifier: AGPL-3.0-or-later
"""Simple-mode event enum → bus-topic pattern expansion.

The UI's Simple mode hides the NATS-style wildcard syntax behind three
friendly choices. Storage is always the expanded pattern list — the
enum exists only at the API boundary.
"""
from __future__ import annotations


# Patterns map to the bus topic hierarchy shipped by DEBT-031's worker
# rollout (see `decnet/bus/topics.py`):
#   - attacker.{observed,fingerprinted,scored,session.started,session.ended}
#   - decky.{id}.{state,traffic}
#   - system.{log,<worker>.health,<worker>.control,bus.health}
SIMPLE_EVENT_PATTERNS: dict[str, list[str]] = {
    "AttackerDetail": ["attacker.>"],
    "DeckyStatus": ["decky.*.state", "decky.*.traffic"],
    "SystemStatus": ["system.>"],
}


def expand_simple_events(names: list[str]) -> list[str]:
    """Flatten a list of simple-event names into their bus patterns.

    Unknown names are silently dropped — the router layer validates
    against the `SimpleEvent` Literal before calling us, so a bad value
    here means a programming error elsewhere, not user input.
    """
    out: list[str] = []
    for n in names:
        out.extend(SIMPLE_EVENT_PATTERNS.get(n, []))
    return out


def merge_patterns(
    simple: list[str] | None, advanced: list[str] | None
) -> list[str]:
    """Combine simple-event expansions with advanced raw patterns, deduped.

    Order-preserving (simple expansions first, then advanced patterns in
    the order the user supplied them) so operators see deterministic
    patterns in API responses.
    """
    seen: set[str] = set()
    out: list[str] = []
    for p in expand_simple_events(simple or []):
        if p not in seen:
            seen.add(p)
            out.append(p)
    for p in advanced or []:
        if isinstance(p, str) and p and p not in seen:
            seen.add(p)
            out.append(p)
    return out
