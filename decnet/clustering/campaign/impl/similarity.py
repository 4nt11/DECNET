# SPDX-License-Identifier: AGPL-3.0-or-later
"""Similarity-graph primitives for the campaign clusterer.

The campaign clusterer reads ``AttackerIdentity`` rows (the layer below)
and groups them into operations. The graph it builds is **not** the
identity-level graph: identity-level signals don't translate 1:1, and
some that get vetoed at identity level (shared infra) are the *primary
positive signal* at campaign level.

Mirror of ``decnet.clustering.impl.similarity`` for the
identity layer; see that module for the four-tier identity taxonomy.

**Time-agnostic.** Same F7 invariant as the identity layer — edges
MUST depend only on *pairwise relative* offsets, never on absolute
clocks. Shift two identities' session windows by the same Δ and the
edge weights MUST be identical. The temporal-overlap edge below uses
this invariant explicitly.

**Edge families** (from ``development/CAMPAIGN_CLUSTERING.md``):

* **Phase-handoff** — A ends in ``COMMAND_AND_CONTROL`` / ``PERSISTENCE``
  on decky D, B begins ``DISCOVERY`` / ``LATERAL_MOVEMENT`` on D
  within window W. Load-bearing for fixture F5 (multi_operator) — the
  signal the identity-side fingerprint-disagreement veto deliberately
  doesn't try to be.
* **Shared-infra** — Jaccard over aggregated payload-hashes /
  C2-endpoints / decky-set across the identities' member observations.
  Vetoed at identity level (``ed32358``); primary positive signal here.
* **Temporal overlap** — sessions inside a bounded *relative* window.
  Campaigns are operations and operations have bounded duration;
  overlap of distinct identities on shared infra is the canonical
  co-op pattern.
* **Cohort** — ASN-cohort + tooling-cohort weak signals. Defeated alone
  (per F2); useful as supporting weight only.

The functions are pure (no DB, no I/O); the worker maps identities into
:class:`IdentityFeatures` once per tick and feeds these into the graph
builder in a sibling module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

from decnet.util.simhash import hamming64


# ─── Identity-level projection ──────────────────────────────────────────────


@dataclass(frozen=True)
class IdentityFeatures:
    """Minimal projection of an :class:`AttackerIdentity` row.

    Built once per identity by the worker (or per fixture identity in
    tests via :func:`from_synthetic_identity`). Keeping the projection
    tight isolates the campaign-graph code from schema drift on the
    identity layer.
    """

    identity_uuid: str
    """Stable ID — production: ``AttackerIdentity.uuid``."""

    asn_cohort: frozenset[int] = field(default_factory=frozenset)
    """All ASNs observed across the identity's member observations.
    A single rotating actor (F2) appears in many ASNs; the *set*
    overlap is the cohort signal."""

    tooling_cohort: frozenset[str] = field(default_factory=frozenset)
    """Tooling labels (e.g. ``"hydra"``, ``"hping"``) inferred from
    fingerprints / commands. Empty until tooling-attribution lands."""

    payload_hashes: frozenset[str] = field(default_factory=frozenset)
    """Aggregated payload hashes across member observations."""

    c2_endpoints: frozenset[str] = field(default_factory=frozenset)
    """Aggregated C2 endpoints across member observations."""

    kd_digraph_simhash: Optional[int] = None
    """Identity's keystroke-rhythm centroid as a 64-bit int (the
    ``AttackerIdentity.kd_digraph_simhash`` column). ``None`` until the
    identity has enough live-typed sessions for a fingerprint."""

    decky_set: frozenset[str] = field(default_factory=frozenset)
    """Aggregated decky IDs the identity touched."""

    commands_by_phase_on_decky: Mapping[
        tuple[str, str], tuple[str, ...]
    ] = field(default_factory=dict)
    """``(decky_id, UKCPhase.value)`` → ordered command sequence
    observed on that decky in that phase. Required for the
    phase-handoff edge — same decky is the join key. Empty when
    ``commands_by_phase`` is unavailable on the production-row
    adapter (deferred per TODO.md until log-mining lands)."""

    session_windows: tuple[tuple[float, float], ...] = ()
    """Per-session ``(start_ts, end_ts)`` tuples in seconds since
    epoch. Used ONLY for pairwise relative deltas — never compared
    to an absolute clock. F7 (slow_burn) invariance check verifies
    that adding Δ to every entry on both sides yields the same edge
    weight."""

    last_phase_per_decky: Mapping[str, str] = field(default_factory=dict)
    """``decky_id`` → last UKC phase observed on that decky. The
    "from" side of a phase handoff."""

    first_phase_per_decky: Mapping[str, str] = field(default_factory=dict)
    """``decky_id`` → first UKC phase observed on that decky. The
    "to" side of a phase handoff."""

    last_seen_per_decky: Mapping[str, float] = field(default_factory=dict)
    """``decky_id`` → last activity timestamp on that decky. Pairs
    with :attr:`first_seen_per_decky` to compute pairwise handoff
    gap relative to the two identities (no absolute clock)."""

    first_seen_per_decky: Mapping[str, float] = field(default_factory=dict)
    """``decky_id`` → first activity timestamp on that decky."""


# ─── Phase-handoff edge ─────────────────────────────────────────────────────


#: Phases that mark a *handoff-out* — operator A is finished setting
#: up a foothold and the next operator can step in. Drawn from the
#: STAGE_IN tail (PERSISTENCE / COMMAND_AND_CONTROL) per the UKC
#: vocabulary; expanding this set is a tunable knob.
HANDOFF_OUT_PHASES: frozenset[str] = frozenset({
    "command_and_control",
    "persistence",
})

#: Phases that mark a *handoff-in* — operator B picks up a prepared
#: foothold and starts operating through the network. STAGE_THROUGH
#: head (DISCOVERY / LATERAL_MOVEMENT).
HANDOFF_IN_PHASES: frozenset[str] = frozenset({
    "discovery",
    "lateral_movement",
})

#: Default handoff-window in seconds. The "B starts within W of A's
#: end" guard. Bounded relative to the pair — fixture F7 invariant
#: still holds because shifting both timestamps preserves the gap.
DEFAULT_HANDOFF_WINDOW_S: float = 24 * 3600.0  # 24h


def phase_handoff_weight(
    a: IdentityFeatures,
    b: IdentityFeatures,
    window_s: float = DEFAULT_HANDOFF_WINDOW_S,
) -> float:
    """Phase-handoff edge — the load-bearing F5 signal.

    Returns ``1.0`` if there exists a decky D such that EITHER:

    * A's last phase on D is in :data:`HANDOFF_OUT_PHASES`, B's first
      phase on D is in :data:`HANDOFF_IN_PHASES`, and B's first
      activity on D is within ``window_s`` AFTER A's last activity
      on D, OR
    * the symmetric case with A and B swapped.

    Returns ``0.0`` when no shared decky has a matching out→in pair
    within window. Window comparison is on the *gap* (a single
    subtraction) — pairwise-relative, so F7 invariance holds.
    """
    return max(
        _directed_handoff(a, b, window_s),
        _directed_handoff(b, a, window_s),
    )


def _directed_handoff(
    out: IdentityFeatures, in_: IdentityFeatures, window_s: float,
) -> float:
    shared = set(out.last_phase_per_decky) & set(in_.first_phase_per_decky)
    for decky in shared:
        out_phase = out.last_phase_per_decky.get(decky)
        in_phase = in_.first_phase_per_decky.get(decky)
        if out_phase not in HANDOFF_OUT_PHASES:
            continue
        if in_phase not in HANDOFF_IN_PHASES:
            continue
        out_t = out.last_seen_per_decky.get(decky)
        in_t = in_.first_seen_per_decky.get(decky)
        if out_t is None or in_t is None:
            continue
        gap = in_t - out_t
        if 0.0 <= gap <= window_s:
            return 1.0
    return 0.0


# ─── Shared-infra edge ──────────────────────────────────────────────────────


def shared_infra_weight(a: IdentityFeatures, b: IdentityFeatures) -> float:
    """Jaccard over payload-hashes ∪ C2-endpoints.

    Excludes ``decky_set`` deliberately: decky overlap is a *fleet
    scarcity* artifact (a small fleet means many distinct campaigns
    hit the same deckies) and would fuse F1's two unrelated campaigns
    on shared targeting. Payload hashes and C2 endpoints are
    operational artifacts; distinct campaigns rarely share them.

    At identity level this gets vetoed by the fingerprint-disagreement
    rule (``ed32358``); at campaign level it's the *primary* positive
    signal — distinct identities sharing payload + C2 is the canonical
    co-op pattern (F5 multi_operator).

    The decky-overlap signal lives in :func:`cohort_weight` instead
    where its weak-tier multiplier prevents F1-style false merges.

    Returns Jaccard across the union of the two set families,
    ``0.0`` when both sides are empty.
    """
    a_set = a.payload_hashes | a.c2_endpoints
    b_set = b.payload_hashes | b.c2_endpoints
    if not a_set and not b_set:
        return 0.0
    union = a_set | b_set
    if not union:
        return 0.0
    return len(a_set & b_set) / len(union)


# ─── Temporal-overlap edge ──────────────────────────────────────────────────


def temporal_overlap_weight(
    a: IdentityFeatures, b: IdentityFeatures,
) -> float:
    """Pairwise-relative temporal overlap fraction.

    Returns the fraction of A's total session time that overlaps any
    B session, capped at ``1.0``. Pairwise-relative: the value is
    invariant under a uniform Δ-shift of every timestamp on both
    sides (F7 fixture's invariant). Returns ``0.0`` when either side
    has no session windows.

    Two non-cooperating actors with bounded operations rarely overlap
    by chance; co-op campaigns overlap heavily. Defeated alone (one
    overlapping minute means little) — combined with shared-infra
    or handoff it pulls a pair over threshold.
    """
    if not a.session_windows or not b.session_windows:
        return 0.0
    a_total = sum(end - start for start, end in a.session_windows)
    if a_total <= 0:
        return 0.0
    overlap = 0.0
    for a_start, a_end in a.session_windows:
        for b_start, b_end in b.session_windows:
            lo = max(a_start, b_start)
            hi = min(a_end, b_end)
            if hi > lo:
                overlap += hi - lo
    return min(1.0, overlap / a_total)


# ─── Cohort edges ───────────────────────────────────────────────────────────


def cohort_weight(a: IdentityFeatures, b: IdentityFeatures) -> float:
    """ASN-cohort + tooling-cohort + decky-overlap weak signal.

    Jaccard over the union of ASN cohort, tooling cohort, and decky
    set. F2's failure mode (one identity rotating across many ASNs)
    doesn't apply at *campaign* level — but multiple identities
    cooperating out of the same hosting cohort is plausible co-op
    evidence. Decky overlap lives here (not in :func:`shared_infra`)
    because decky scarcity in a small honeypot fleet would otherwise
    fuse unrelated campaigns hitting the same SSH targets (F1
    shared_wordlist).

    Weak by design: the combined-weight tier multiplier keeps this
    from crossing threshold alone.
    """
    a_set: frozenset = frozenset(
        {("asn", str(x)) for x in a.asn_cohort}
        | {("tool", x) for x in a.tooling_cohort}
        | {("decky", x) for x in a.decky_set}
    )
    b_set: frozenset = frozenset(
        {("asn", str(x)) for x in b.asn_cohort}
        | {("tool", x) for x in b.tooling_cohort}
        | {("decky", x) for x in b.decky_set}
    )
    if not a_set and not b_set:
        return 0.0
    union = a_set | b_set
    if not union:
        return 0.0
    return len(a_set & b_set) / len(union)


# ─── Combined campaign-level weight ─────────────────────────────────────────


#: Tier multipliers for the campaign graph. Tuned so:
#:
#: * Phase-handoff alone (max 1.0) crosses threshold — a clean
#:   F5-style handoff is sufficient evidence on its own.
#: * Shared-infra alone (max 1.0) crosses threshold — payload+C2
#:   overlap is the canonical co-op signal (F5 multi_operator's
#:   intended pass condition; decky overlap was deliberately moved
#:   to :func:`cohort_weight` to avoid F1's false merge on shared
#:   targeting).
#: * Temporal overlap alone (max 1.0) yields 0.4 — supporting weight.
#: * Cohort alone (max 1.0) yields 0.1 — defeats F1's shared-decky
#:   failure mode and F2's rotating-ASN one.
#:
#: F1 shared_wordlist: payload+C2 = ∅ on both sides → shared_infra =
#: 0; ASN+decky overlap fires cohort but at 0.1 stays well below
#: threshold. F2 vpn_hopping is folded by the identity layer first,
#: so the campaign clusterer sees one identity → one campaign.
#: Max Hamming distance (of 64 bits) at which two identities' keystroke-
#: rhythm centroids still count as the same typist. Beyond this the
#: biometric contributes nothing. Conservative — same-typist hashes are
#: typically <6 bits apart (see toolchain.payload.payload_simhash notes).
KD_HAMMING_MAX: int = 8

CAMPAIGN_TIER_WEIGHTS: dict[str, float] = {
    "phase_handoff": 1.0,
    "shared_infra": 1.0,
    "temporal_overlap": 0.4,
    "cohort": 0.1,
    # Keystroke biometric is a strong *supporting* signal — 0.6 means a
    # typing match plus temporal overlap (0.4) reaches threshold, but a
    # typing match alone never merges two identities (FP guard: terminal
    # timing is noisy and the bucketing is coarse).
    "keystroke": 0.6,
}

#: Threshold a combined campaign-edge weight must meet to survive
#: into the similarity graph.
CAMPAIGN_EDGE_THRESHOLD: float = 1.0


def combined_campaign_weight(
    a: IdentityFeatures,
    b: IdentityFeatures,
    *,
    handoff_window_s: float = DEFAULT_HANDOFF_WINDOW_S,
) -> float:
    """Sum of all four tier scores, weighted by
    :data:`CAMPAIGN_TIER_WEIGHTS`.

    The campaign-clusterer worker compares this against
    :data:`CAMPAIGN_EDGE_THRESHOLD` to decide whether to draw an
    edge. Pure / time-agnostic — F7 invariant preserved.
    """
    return (
        CAMPAIGN_TIER_WEIGHTS["phase_handoff"]
        * phase_handoff_weight(a, b, handoff_window_s)
        + CAMPAIGN_TIER_WEIGHTS["shared_infra"] * shared_infra_weight(a, b)
        + CAMPAIGN_TIER_WEIGHTS["temporal_overlap"]
        * temporal_overlap_weight(a, b)
        + CAMPAIGN_TIER_WEIGHTS["cohort"] * cohort_weight(a, b)
        + CAMPAIGN_TIER_WEIGHTS["keystroke"] * keystroke_weight(a, b)
    )


def keystroke_weight(a: IdentityFeatures, b: IdentityFeatures) -> float:
    """Keystroke-rhythm proximity ∈ [0, 1] from the two identities'
    digraph-SimHash centroids.

    Graded by Hamming distance: identical rhythm → 1.0, fading linearly
    to 0.0 at ``KD_HAMMING_MAX`` bits apart (and beyond). ``0.0`` when
    either identity has no centroid yet. Pure / time-agnostic.
    """
    if a.kd_digraph_simhash is None or b.kd_digraph_simhash is None:
        return 0.0
    dist = hamming64(a.kd_digraph_simhash, b.kd_digraph_simhash)
    if dist >= KD_HAMMING_MAX:
        return 0.0
    return 1.0 - dist / KD_HAMMING_MAX


# ─── Adapter for synthetic-fixture tests ────────────────────────────────────


def from_synthetic_identity(att, identity_uuid: Optional[str] = None) -> IdentityFeatures:
    """Build an :class:`IdentityFeatures` from a ``SyntheticAttacker``.

    Treats one ``SyntheticAttacker`` as one identity — adequate for
    fixture validation where the campaign-clusterer reads identities
    not raw observations. The worker's production-row adapter
    (commit 3) builds the same shape from real ``AttackerIdentity``
    rows + their member observations.

    Lives here so test code doesn't import the factory shape into the
    production module — the adapter is a documented integration point.
    """
    payload_hashes: set[str] = set()
    c2_endpoints: set[str] = set()
    decky_set: set[str] = set()
    asn_cohort: set[int] = set()
    if att.asn is not None:
        asn_cohort.add(att.asn)

    commands_by_phase_on_decky: dict[tuple[str, str], list[str]] = {}
    last_phase_per_decky: dict[str, str] = {}
    first_phase_per_decky: dict[str, str] = {}
    last_seen_per_decky: dict[str, float] = {}
    first_seen_per_decky: dict[str, float] = {}
    session_windows: list[tuple[float, float]] = []

    # SyntheticSession order is the campaign DSL's emission order, which
    # is monotonically time-ordered by construction. We rely on that to
    # extract first/last phase per decky.
    for s in att.sessions:
        if s.payload_hash:
            payload_hashes.add(s.payload_hash)
        if s.c2_callback:
            c2_endpoints.add(s.c2_callback)
        decky = getattr(s, "decky", None) or getattr(s, "decky_id", None)
        if decky:
            decky_set.add(decky)
        # SyntheticSession exposes ``started_at`` (datetime) +
        # ``duration_s``; the production-row adapter (commit 3) gets
        # ``start_ts``/``end_ts`` directly. Support both.
        started_at = getattr(s, "started_at", None)
        duration_s = getattr(s, "duration_s", None)
        if started_at is not None:
            ts_start = started_at.timestamp()
            ts_end = ts_start + (float(duration_s) if duration_s else 0.0)
        else:
            ts_start = getattr(s, "start_ts", None)
            ts_end = getattr(s, "end_ts", None)
        if ts_start is not None and ts_end is not None:
            session_windows.append((float(ts_start), float(ts_end)))
        phase_value = s.phase.value if hasattr(s, "phase") else None
        if decky and phase_value:
            key = (decky, phase_value)
            if s.commands:
                commands_by_phase_on_decky.setdefault(key, []).extend(s.commands)
            if decky not in first_phase_per_decky:
                first_phase_per_decky[decky] = phase_value
                if ts_start is not None:
                    first_seen_per_decky[decky] = float(ts_start)
            last_phase_per_decky[decky] = phase_value
            if ts_end is not None:
                last_seen_per_decky[decky] = float(ts_end)
            elif ts_start is not None:
                last_seen_per_decky[decky] = float(ts_start)

    return IdentityFeatures(
        identity_uuid=identity_uuid or att.attacker_id,
        asn_cohort=frozenset(asn_cohort),
        tooling_cohort=frozenset(),
        payload_hashes=frozenset(payload_hashes),
        c2_endpoints=frozenset(c2_endpoints),
        decky_set=frozenset(decky_set),
        commands_by_phase_on_decky={
            k: tuple(v) for k, v in commands_by_phase_on_decky.items()
        },
        session_windows=tuple(session_windows),
        last_phase_per_decky=dict(last_phase_per_decky),
        first_phase_per_decky=dict(first_phase_per_decky),
        last_seen_per_decky=dict(last_seen_per_decky),
        first_seen_per_decky=dict(first_seen_per_decky),
    )


__all__ = [
    "IdentityFeatures",
    "phase_handoff_weight",
    "shared_infra_weight",
    "temporal_overlap_weight",
    "cohort_weight",
    "keystroke_weight",
    "combined_campaign_weight",
    "from_synthetic_identity",
    "HANDOFF_OUT_PHASES",
    "HANDOFF_IN_PHASES",
    "DEFAULT_HANDOFF_WINDOW_S",
    "CAMPAIGN_TIER_WEIGHTS",
    "CAMPAIGN_EDGE_THRESHOLD",
    "KD_HAMMING_MAX",
]
