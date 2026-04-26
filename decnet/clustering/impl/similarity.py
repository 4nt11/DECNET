"""Similarity-graph primitives for the connected-components clusterer.

Each function takes two :class:`Observation` projections and returns a
similarity score in ``[0.0, 1.0]``. The connected-components impl
(landing in subsequent commits) decides how to combine these into a
single edge weight, applies a threshold, and runs union-find.

**Time-agnostic.** Edges MUST NOT depend on observation timestamps.
Fixture 7 (``slow_burn``) proves recency-decay clustering fragments
multi-month APT campaigns; the production graph cannot silently expire
old edges. Timestamps are still useful for *audit* (the ``first_seen``
on the resulting identity row) but never for *similarity*.

**Weight tiers** (from `development/IDENTITY_RESOLUTION.md`):

* High — JA3 / HASSH / payload-hash / C2-callback exact match. Stable
  signals an attacker can't cheaply rotate. A single high-tier match
  supports identity strongly.
* Medium — command-sequence Jaccard, bucketed by UKC phase. Tooling
  habits leak through command order; phase-bucketing avoids comparing
  a Discovery cmd-list to an Exploitation one.
* Low — credential-attempt-set Jaccard. Defeated alone by fixture 1
  (``shared_wordlist``) where two campaigns share rockyou but diverge
  on infra.
* Very low — ASN match. Defeated alone by fixture 2 (``vpn_hopping``)
  where one identity rotates across many ASNs.

The functions are pure (no DB, no I/O); the worker maps observations
into :class:`Observation` once per tick and feeds these into the
graph builder.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

# ─── Observation projection ─────────────────────────────────────────────────


@dataclass(frozen=True)
class Observation:
    """Minimal projection of a per-IP attacker observation.

    Built once per ``Attacker`` row by the worker (or per
    ``SyntheticAttacker`` in tests via :func:`from_synthetic`).
    Keeping the projection tight isolates the graph code from schema
    drift on either side.

    All set-typed fields are :class:`frozenset` so they hash and so
    callers don't accidentally mutate them mid-pass.
    """

    observation_id: str
    """Stable ID — for production, the ``Attacker.uuid``; for tests,
    the ``SyntheticAttacker.attacker_id``."""

    ja3: Optional[str] = None
    hassh: Optional[str] = None
    asn: Optional[int] = None

    payload_hashes: frozenset[str] = field(default_factory=frozenset)
    c2_endpoints: frozenset[str] = field(default_factory=frozenset)
    credentials: frozenset[tuple[str, str]] = field(default_factory=frozenset)

    commands_by_phase: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """``UKCPhase.value`` → ordered command sequence observed in that
    phase. Empty dict when no command-bearing sessions were seen."""


# ─── Edge functions ─────────────────────────────────────────────────────────


def high_weight_edge(a: Observation, b: Observation) -> float:
    """JA3 / HASSH / payload-hash / C2-endpoint exact match.

    Returns ``1.0`` if any of the four exact-match signals agrees
    (non-null on both sides), ``0.0`` otherwise. Single-signal high-tier
    agreement is by design enough to support identity — these are the
    signals the design doc calls out as "stable signals an attacker
    can't cheaply rotate."

    JA4 will join this tier as a sibling of JA3 once the prober emits
    it (``ATTACKER_FINGERPRINTED`` already carries a JA4 slot in
    ``AttackerIdentity``); the function shape doesn't change.
    """
    if a.ja3 is not None and a.ja3 == b.ja3:
        return 1.0
    if a.hassh is not None and a.hassh == b.hassh:
        return 1.0
    if a.payload_hashes and b.payload_hashes and (a.payload_hashes & b.payload_hashes):
        return 1.0
    if a.c2_endpoints and b.c2_endpoints and (a.c2_endpoints & b.c2_endpoints):
        return 1.0
    return 0.0


def medium_weight_edge(a: Observation, b: Observation) -> float:
    """Phase-bucketed command-sequence Jaccard.

    For each UKC phase observed on both sides, computes the Jaccard
    similarity of the command sets (multisets collapsed to sets — the
    *order* signal is reserved for a future feature, this commit is
    the scaffolding). Returns the **maximum** Jaccard across shared
    phases, so a single strong phase match isn't averaged away by a
    different phase where the actors diverge.

    Phase-bucketing matters: comparing a Discovery cmd-list to an
    Exploitation one is meaningless. Both actors had to be in the
    same phase for the comparison to count.

    Returns ``0.0`` when no phase is observed on both sides.
    """
    shared_phases = set(a.commands_by_phase) & set(b.commands_by_phase)
    if not shared_phases:
        return 0.0
    best = 0.0
    for phase in shared_phases:
        sa = set(a.commands_by_phase[phase])
        sb = set(b.commands_by_phase[phase])
        if not sa and not sb:
            continue
        union = sa | sb
        if not union:
            continue
        j = len(sa & sb) / len(union)
        if j > best:
            best = j
    return best


def low_weight_edge(a: Observation, b: Observation) -> float:
    """Credential-attempt-set Jaccard.

    Returns the Jaccard of ``(username, password)`` tuples. Two campaigns
    burning the same wordlist will score high here — fixture 1 proves
    this signal is dangerous in isolation. The connected-components
    impl combines this with other signals; alone it must not push a
    pair over threshold.

    Returns ``0.0`` when either side attempted no credentials, or when
    the union is empty.
    """
    if not a.credentials or not b.credentials:
        return 0.0
    union = a.credentials | b.credentials
    if not union:
        return 0.0
    return len(a.credentials & b.credentials) / len(union)


def very_low_weight_edge(a: Observation, b: Observation) -> float:
    """ASN equality.

    Returns ``1.0`` iff both observations have a non-null ASN and they
    match. Fixture 2 (``vpn_hopping``) proves ASN-only clustering is
    a failure mode — one identity legitimately rotates across many
    ASNs. The combination logic in the connected-components impl
    weights this so that ASN agreement alone never crosses threshold.
    """
    if a.asn is None or b.asn is None:
        return 0.0
    return 1.0 if a.asn == b.asn else 0.0


# ─── Combined weight ────────────────────────────────────────────────────────

#: Tier multipliers applied to the per-tier edge scores when combining
#: into a single weight. Tuned so that:
#:
#: * High-tier agreement alone (1.0) crosses the 1.0 threshold.
#: * Medium-tier alone (max 1.0) yields 0.6 — below threshold.
#: * Low-tier alone (max 1.0) yields 0.2 — defeats fixture 1's
#:   credential-overlap-only failure mode.
#: * Very-low alone (max 1.0) yields 0.05 — defeats fixture 2's
#:   ASN-rotation failure mode.
#:
#: The ratio between tiers matters more than the absolute values: a
#: tier should never combine its way past threshold without help from
#: a stronger one.
TIER_WEIGHTS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.2,
    "very_low": 0.05,
}

#: Threshold a combined edge weight must meet to survive into the
#: similarity graph. The connected-components impl drops anything
#: under this before running union-find.
EDGE_THRESHOLD = 1.0


def combined_edge_weight(a: Observation, b: Observation) -> float:
    """Sum of all four tier scores, weighted by :data:`TIER_WEIGHTS`.

    Each per-tier function returns a score in ``[0, 1]``; the
    weighted sum lets stronger tiers dominate without letting weaker
    ones combine their way past threshold.

    The connected-components clusterer compares this against
    :data:`EDGE_THRESHOLD` to decide whether to draw an edge. Pure /
    time-agnostic — fixture 7 forbids recency-decay weighting.

    Commits 5–7 land each tier in the call site:

    * Commit 5 (this commit): high + medium.
    * Commit 6: + phase-handoff (a separate edge family, not a tier).
    * Commit 7: + low + very_low.

    Until commit 7 lands, the low / very_low contributions stay zero
    by virtue of the underlying functions returning ``0.0`` whenever
    their inputs are missing. The combination is forward-compatible.
    """
    return (
        TIER_WEIGHTS["high"] * high_weight_edge(a, b)
        + TIER_WEIGHTS["medium"] * medium_weight_edge(a, b)
        + TIER_WEIGHTS["low"] * low_weight_edge(a, b)
        + TIER_WEIGHTS["very_low"] * very_low_weight_edge(a, b)
    )


# ─── Adapter for the synthetic-corpus tests ─────────────────────────────────


def from_synthetic(att) -> Observation:  # type: ignore[no-untyped-def]
    """Build an :class:`Observation` from a ``SyntheticAttacker``.

    Lives here so test code doesn't import the factory shape into the
    production module — the adapter is a documented integration point.
    Imported lazily by callers; the production worker uses a parallel
    adapter from :class:`Attacker` rows once that lands.
    """
    payload_hashes: set[str] = set()
    c2_endpoints: set[str] = set()
    credentials: set[tuple[str, str]] = set()
    commands_by_phase: dict[str, list[str]] = {}

    for s in att.sessions:
        if s.payload_hash:
            payload_hashes.add(s.payload_hash)
        if s.c2_callback:
            c2_endpoints.add(s.c2_callback)
        for cred in s.credentials_tried:
            credentials.add(tuple(cred))
        if s.commands:
            commands_by_phase.setdefault(s.phase.value, []).extend(s.commands)

    return Observation(
        observation_id=att.attacker_id,
        ja3=att.ja3,
        hassh=att.hassh,
        asn=att.asn,
        payload_hashes=frozenset(payload_hashes),
        c2_endpoints=frozenset(c2_endpoints),
        credentials=frozenset(credentials),
        commands_by_phase={k: tuple(v) for k, v in commands_by_phase.items()},
    )


__all__ = [
    "Observation",
    "high_weight_edge",
    "medium_weight_edge",
    "low_weight_edge",
    "very_low_weight_edge",
    "combined_edge_weight",
    "from_synthetic",
    "EDGE_THRESHOLD",
    "TIER_WEIGHTS",
]
