"""Canonical topic hierarchy for the DECNET ServiceBus.

Locked early so consumers can subscribe with stable wildcard patterns.
Adding new topic families is fine; **renaming** existing ones is a breaking
change for every subscriber and requires a coordinated rollout.

Token structure (NATS-style, dot-separated):

    topology.{topology_id}.mutation.{state}
    topology.{topology_id}.status
    decky.{decky_id}.state
    decky.{decky_id}.traffic
    attacker.observed
    system.log
    system.bus.health

Wildcards (per :func:`decnet.bus.base.matches`):

* ``*`` matches exactly one token.
* ``>`` matches one-or-more trailing tokens (so ``topology.>`` matches
  ``topology.abc.status`` but not the bare root ``topology``).
"""
from __future__ import annotations

# ─── Root prefixes ───────────────────────────────────────────────────────────

TOPOLOGY = "topology"
DECKY = "decky"
ATTACKER = "attacker"
SYSTEM = "system"


# ─── Leaf event-type constants (the last segment of each topic) ──────────────

# Topology mutation lifecycle states — keep in sync with TopologyMutation.state
# in decnet/web/db/models.py; the bus topic mirrors the DB state machine.
MUTATION_ENQUEUED = "enqueued"
MUTATION_APPLYING = "applying"
MUTATION_APPLIED = "applied"
MUTATION_FAILED = "failed"

# Topology-level status transitions (topology.{id}.status): fires when the
# topology row's status column changes (pending/deploying/active/degraded/failed).
TOPOLOGY_STATUS = "status"

# Decky-level event types (second token).
DECKY_STATE = "state"
DECKY_TRAFFIC = "traffic"

# System event types.
SYSTEM_LOG = "log"
SYSTEM_BUS_HEALTH = "bus.health"


# ─── Builders ────────────────────────────────────────────────────────────────

def topology_mutation(topology_id: str, state: str) -> str:
    """Build ``topology.<id>.mutation.<state>``.

    *state* should be one of the ``MUTATION_*`` constants.
    """
    _reject_tokens(topology_id, state)
    return f"{TOPOLOGY}.{topology_id}.mutation.{state}"


def topology_status(topology_id: str) -> str:
    """Build ``topology.<id>.status``."""
    _reject_tokens(topology_id)
    return f"{TOPOLOGY}.{topology_id}.{TOPOLOGY_STATUS}"


def decky(decky_id: str, event_type: str) -> str:
    """Build ``decky.<id>.<event_type>``.

    *event_type* is typically one of ``DECKY_STATE`` or ``DECKY_TRAFFIC``.
    """
    _reject_tokens(decky_id, event_type)
    return f"{DECKY}.{decky_id}.{event_type}"


def system(event_type: str) -> str:
    """Build ``system.<event_type>``.

    *event_type* may itself contain dots (e.g. ``bus.health``) — we don't
    re-validate the already-constant leaves; this just prefixes.
    """
    if not event_type:
        raise ValueError("system topic requires a non-empty event_type")
    return f"{SYSTEM}.{event_type}"


def _reject_tokens(*parts: str) -> None:
    """Reject topic segments that would break NATS-style tokenization.

    Dots, wildcards, whitespace, and empty strings in a *segment* would
    silently corrupt the hierarchy (e.g. ``topology.a.b.status`` for a
    ``topology_id`` of ``"a.b"``).  Raise early at the builder instead of
    shipping a malformed topic to the wire.
    """
    for p in parts:
        if not p:
            raise ValueError("topic segment must not be empty")
        if "." in p or "*" in p or ">" in p or any(c.isspace() for c in p):
            raise ValueError(
                f"topic segment {p!r} may not contain '.', '*', '>', or whitespace"
            )
