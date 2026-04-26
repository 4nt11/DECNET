"""
Shared helpers for fixture-driven clustering tests.

Each fixture lives at `tests/fixtures/campaigns/<name>.yaml` with paired
`<name>.expected.yaml` bound file. The harness here keeps every per-
fixture test file down to "load corpus → predict → assert bounds" without
copy-pasting the bound-walk loop or reference clusterers across files.

Reference clusterers are provided as the algorithm under test in each
fixture's bound assertions; their names describe the *signal* they
cluster on, not the quality of the result.

* `identity_clusterer` — every attacker is its own cluster. Trivially
  passes any fixture whose ground truth is all singletons (lone_wolf,
  shared_wordlist before merge, etc). Useful as a green baseline while
  the real connected-components algorithm is under construction.

* `fingerprint_clusterer` — groups attackers by ``(ja3, hassh)``.
  Approximates the "stable signals an attacker can't cheaply rotate"
  arm of the planned similarity graph (see IDENTITY_RESOLUTION.md
  Premise). Folds rotated-IP observations of one actor into one
  cluster when the actor's JA3 + HASSH stay stable. Attackers whose
  fingerprints are both NULL (typical of un-fingerprinted noise
  scanners) are treated as un-mergeable — each becomes its own
  singleton — so this clusterer doesn't trivially fuse all noise
  into one mega-cluster.

* `credential_jaccard_clusterer` — deliberately-bad reference that
  merges any two attackers whose credential-attempt sets overlap above
  a threshold. Exists so fixtures like `shared_wordlist` can prove
  they fail a clusterer that relies on credential overlap alone — the
  whole point of fixture #1.

* `asn_clusterer` — deliberately-bad reference that groups attackers
  by source ASN. Exists so fixtures like `vpn_hopping` (fixture #2)
  can prove they fail a clusterer that treats ASN match as a
  high-weight signal — VPN/proxy hopping shatters ASN within a single
  identity and a clusterer that leans on it tanks completeness.

* `time_window_clusterer` — deliberately-bad reference that unions
  attackers whose session time-ranges are within ``gap_days`` of each
  other. Exists so fixtures like `paused_campaign` (fixture #4) can
  prove they fail a clusterer that treats short-window time proximity
  as a primary signal — operators pause, sleep, take weekends.

* `c2_callback_clusterer` — union-find on overlapping C2 callback
  sets. Pass-clusterer for fixture 5 (multi_operator), where two
  operators with distinct tooling share a C2 endpoint as the
  load-bearing campaign signal. Attackers with no C2 endpoints
  become their own singleton.

* `shift_clusterer` — deliberately-bad reference that buckets
  attackers by majority session-start hour into night/day/swing.
  Exists so fixture 5 can prove they fail a clusterer that treats
  shift schedule as a primary signal — operators on different
  schedules can still share a campaign.

* `composite_signals_clusterer` — union-find that combines
  ``(ja3, hassh)`` match OR shared C2 callback into the same
  cluster. Approximates the planned similarity graph well enough
  to score the combined-corpus fixture (fixture 6, noise_floor).

* `recency_decay_clusterer` — deliberately-bad reference that
  starts from the same composite signal graph but weights each
  edge by ``exp(-time_distance / half_life_days)`` and drops
  edges below a threshold. Adversarial reference for fixture 7
  (slow_burn): the canonical production failure mode where a
  graph clusterer with recency decay fragments long-running
  APT campaigns by silently expiring multi-week-old edges.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from tests.clustering.metrics import score
from tests.factories.campaign_factory import GeneratedCorpus

PredictFn = Callable[[GeneratedCorpus], dict[str, str]]


def assert_fixture_bounds(
    corpus: GeneratedCorpus,
    predict: PredictFn,
    expected_path: str | Path,
    *,
    truth_level: str = "campaign",
) -> dict[str, float]:
    """
    Run `predict` against the corpus, score against ground truth, and
    assert every metric meets the floor declared in `expected_path`.

    ``truth_level`` selects the oracle: ``"campaign"`` (default) for
    campaign-clustering fixtures, ``"identity"`` for identity-resolution
    fixtures (where the clusterer's job is to fold N rotated-IP
    observations into one identity), or ``"actor"`` for completeness.

    Returns the observed metrics dict so callers can do additional
    assertions (e.g. "homogeneity is *exactly* 1.0 for this fixture").
    """
    bounds = yaml.safe_load(Path(expected_path).read_text(encoding="utf-8"))
    truth = corpus.truth_labels(level=truth_level)
    pred = predict(corpus)
    metrics = score(truth, pred)

    failures = []
    for name, bound in bounds.items():
        observed = metrics[name]
        floor = bound["min"]
        if observed < floor:
            failures.append(f"{name}={observed:.3f} < min {floor:.3f}")
    assert not failures, (
        "fixture bounds violated: " + "; ".join(failures)
        + f" (full metrics: {metrics})"
    )
    return metrics


# ─── Reference clusterers ───────────────────────────────────────────────────


def identity_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Every attacker → its own cluster. Placeholder until §4 algorithm lands."""
    return {a.attacker_id: f"cluster-{a.attacker_id}" for a in corpus.attackers}


def fingerprint_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Group by ``(ja3, hassh)``. Un-fingerprinted rows stay singleton.

    Approximates the stable-signal arm of the planned similarity graph;
    the real algorithm in `decnet/clustering/` will extend this with
    payload simhashes, C2 callback overlap, and phase-handoff edges.
    """
    pred: dict[str, str] = {}
    for att in corpus.attackers:
        if att.ja3 is None and att.hassh is None:
            # No fingerprint to share — un-mergeable, own cluster.
            pred[att.attacker_id] = f"fp-singleton-{att.attacker_id}"
        else:
            pred[att.attacker_id] = f"fp::{att.ja3}::{att.hassh}"
    return pred


def asn_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Group by source ASN. Deliberately-bad — see fixture 2."""
    return {a.attacker_id: f"asn-{a.asn}" for a in corpus.attackers}


def _union_find(ids: list[str]) -> tuple[
    dict[str, str], Callable[[str], str], Callable[[str, str], None]
]:
    """Return (parent, find, union) for a fresh union-find over ``ids``."""
    parent: dict[str, str] = {aid: aid for aid in ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    return parent, find, union


def c2_callback_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Union attackers whose session-collected C2 callback sets overlap.

    Attackers with no C2 callbacks become their own singleton (an
    un-fingerprinted opportunistic scanner has no link to anyone).
    """
    callbacks: dict[str, set[str]] = {}
    for att in corpus.attackers:
        callbacks[att.attacker_id] = {
            s.c2_callback for s in att.sessions if s.c2_callback
        }

    ids = list(callbacks.keys())
    _parent, find, union = _union_find(ids)

    for i, a in enumerate(ids):
        sa = callbacks[a]
        if not sa:
            continue
        for b in ids[i + 1 :]:
            sb = callbacks[b]
            if not sb:
                continue
            if sa & sb:
                union(a, b)

    pred: dict[str, str] = {}
    for aid in ids:
        if not callbacks[aid]:
            pred[aid] = f"c2-none-{aid}"
        else:
            pred[aid] = f"c2-{find(aid)}"
    return pred


def shift_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Bucket attackers by majority session-start hour into night /
    day / swing. Deliberately-bad — see fixture 5.

    Buckets:
      * night  — hours [22, 23, 0, 1, 2, 3, 4, 5]
      * day    — hours [6, 7, 8, 9, 10, 11, 12, 13]
      * swing  — hours [14, 15, 16, 17, 18, 19, 20, 21]

    Attackers with no sessions become their own singleton.
    """
    night = {22, 23, 0, 1, 2, 3, 4, 5}
    day = {6, 7, 8, 9, 10, 11, 12, 13}

    def bucket(hour: int) -> str:
        if hour in night:
            return "night"
        if hour in day:
            return "day"
        return "swing"

    pred: dict[str, str] = {}
    for att in corpus.attackers:
        if not att.sessions:
            pred[att.attacker_id] = f"shift-none-{att.attacker_id}"
            continue
        counts: dict[str, int] = {}
        for s in att.sessions:
            b = bucket(s.started_at.hour)
            counts[b] = counts.get(b, 0) + 1
        majority = max(counts, key=lambda k: counts[k])
        pred[att.attacker_id] = f"shift-{majority}"
    return pred


def composite_signals_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Union-find combining ``(ja3, hassh)`` match OR overlapping C2
    callback sets. Approximates the stable-signals + C2-overlap arms
    of the planned similarity graph; used as the pass-clusterer for
    fixture 6 where multiple campaigns + noise are scored together.

    Attackers with NO signals (no fingerprint, no C2) stay singleton.
    """
    callbacks: dict[str, set[str]] = {}
    fingerprint: dict[str, tuple[str | None, str | None] | None] = {}
    for att in corpus.attackers:
        callbacks[att.attacker_id] = {
            s.c2_callback for s in att.sessions if s.c2_callback
        }
        if att.ja3 is None and att.hassh is None:
            fingerprint[att.attacker_id] = None
        else:
            fingerprint[att.attacker_id] = (att.ja3, att.hassh)

    ids = list(callbacks.keys())
    _parent, find, union = _union_find(ids)

    # Fingerprint edges.
    by_fp: dict[tuple[str | None, str | None], list[str]] = {}
    for aid, fp in fingerprint.items():
        if fp is None:
            continue
        by_fp.setdefault(fp, []).append(aid)
    for group in by_fp.values():
        anchor = group[0]
        for other in group[1:]:
            union(anchor, other)

    # C2 overlap edges.
    for i, a in enumerate(ids):
        sa = callbacks[a]
        if not sa:
            continue
        for b in ids[i + 1 :]:
            sb = callbacks[b]
            if not sb:
                continue
            if sa & sb:
                union(a, b)

    pred: dict[str, str] = {}
    for aid in ids:
        if fingerprint[aid] is None and not callbacks[aid]:
            pred[aid] = f"composite-singleton-{aid}"
        else:
            pred[aid] = f"composite-{find(aid)}"
    return pred


def recency_decay_clusterer(
    corpus: GeneratedCorpus,
    *,
    half_life_days: float = 14.0,
    threshold: float = 0.5,
) -> dict[str, str]:
    """Composite-signal graph with exponential time decay on edges.

    Same edge construction as ``composite_signals_clusterer``
    (fingerprint match OR overlapping C2), but each edge's weight
    is multiplied by ``exp(-time_distance / half_life_days)`` where
    ``time_distance`` is the gap (in days) between the two attackers'
    session-midpoint timestamps. Edges with decayed weight below
    ``threshold`` are dropped before connected components are
    extracted.

    Deliberately-bad reference for fixture 7 (slow_burn): an APT
    campaign that operates over months will be fragmented by any
    clusterer that silently expires old edges. This is the canonical
    production failure mode for recency-weighted graph clustering on
    long-running threat actors.

    Attackers with no signals or no sessions stay singleton.
    """
    import math
    from datetime import timedelta

    callbacks: dict[str, set[str]] = {}
    fingerprint: dict[str, tuple[str | None, str | None] | None] = {}
    midpoint: dict[str, "object | None"] = {}
    for att in corpus.attackers:
        callbacks[att.attacker_id] = {
            s.c2_callback for s in att.sessions if s.c2_callback
        }
        if att.ja3 is None and att.hassh is None:
            fingerprint[att.attacker_id] = None
        else:
            fingerprint[att.attacker_id] = (att.ja3, att.hassh)
        if att.sessions:
            starts = [s.started_at for s in att.sessions]
            ends = [s.started_at + timedelta(seconds=s.duration_s) for s in att.sessions]
            mid = min(starts) + (max(ends) - min(starts)) / 2
            midpoint[att.attacker_id] = mid
        else:
            midpoint[att.attacker_id] = None

    ids = list(callbacks.keys())
    _parent, find, union = _union_find(ids)

    def edge_strength(a: str, b: str) -> float:
        """Base signal strength before time decay; 1.0 on match, else 0."""
        fa, fb = fingerprint[a], fingerprint[b]
        if fa is not None and fb is not None and fa == fb:
            return 1.0
        sa, sb = callbacks[a], callbacks[b]
        if sa and sb and (sa & sb):
            return 1.0
        return 0.0

    for i, a in enumerate(ids):
        ma = midpoint[a]
        if ma is None:
            continue
        for b in ids[i + 1 :]:
            mb = midpoint[b]
            if mb is None:
                continue
            base = edge_strength(a, b)
            if base <= 0.0:
                continue
            gap_days = abs((ma - mb).total_seconds()) / 86400.0
            weight = base * math.exp(-gap_days / half_life_days)
            if weight >= threshold:
                union(a, b)

    pred: dict[str, str] = {}
    for aid in ids:
        if fingerprint[aid] is None and not callbacks[aid]:
            pred[aid] = f"recency-singleton-{aid}"
        else:
            pred[aid] = f"recency-{find(aid)}"
    return pred


def time_window_clusterer(
    corpus: GeneratedCorpus, *, gap_days: float = 1.0
) -> dict[str, str]:
    """Union-find over attackers, edge if their session time-ranges
    overlap or are within ``gap_days`` of each other.

    Deliberately-bad reference for fixture 4 (paused_campaign): a
    campaign that goes silent for several days will be split into
    "before pause" and "after pause" clusters by this clusterer,
    breaching completeness. The real algorithm must not lean on
    short-window time proximity as a primary signal — operators
    pause, sleep, switch shifts, take weekends. Time bursts are a
    weak hint, not a hard partition.

    Attackers with no sessions become their own singleton cluster.
    """
    from datetime import timedelta

    gap = timedelta(days=gap_days)
    ids = [a.attacker_id for a in corpus.attackers]
    ranges: dict[str, tuple] = {}
    for att in corpus.attackers:
        if not att.sessions:
            continue
        starts = [s.started_at for s in att.sessions]
        ends = [s.started_at + timedelta(seconds=s.duration_s) for s in att.sessions]
        ranges[att.attacker_id] = (min(starts), max(ends))

    parent: dict[str, str] = {aid: aid for aid in ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    keys = list(ranges.keys())
    for i, a in enumerate(keys):
        a_start, a_end = ranges[a]
        for b in keys[i + 1 :]:
            b_start, b_end = ranges[b]
            # Time-distance between the two ranges (0 if they overlap).
            if a_end < b_start:
                separation = b_start - a_end
            elif b_end < a_start:
                separation = a_start - b_end
            else:
                separation = timedelta(0)
            if separation <= gap:
                union(a, b)

    return {aid: find(aid) for aid in ids}


def credential_jaccard_clusterer(
    corpus: GeneratedCorpus, *, threshold: float = 0.5
) -> dict[str, str]:
    """
    Deliberately-bad reference: union-find over attackers, edge whenever
    two attackers' credential-attempt sets have Jaccard ≥ threshold.

    Used to demonstrate that fixtures targeting credential-overlap
    failure modes (fixture 1: shared_wordlist) actually catch a clusterer
    that leans on credential signals alone. NOT the real algorithm.
    """
    # Build per-attacker credential sets.
    creds: dict[str, set[tuple[str, str]]] = {}
    for att in corpus.attackers:
        s: set[tuple[str, str]] = set()
        for sess in att.sessions:
            s.update(sess.credentials_tried)
        creds[att.attacker_id] = s

    # Union-find.
    parent: dict[str, str] = {aid: aid for aid in creds}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    ids = list(creds.keys())
    for i, a in enumerate(ids):
        sa = creds[a]
        if not sa:
            continue
        for b in ids[i + 1 :]:
            sb = creds[b]
            if not sb:
                continue
            inter = len(sa & sb)
            union_size = len(sa | sb)
            if union_size == 0:
                continue
            jaccard = inter / union_size
            if jaccard >= threshold:
                union(a, b)

    return {aid: find(aid) for aid in ids}
