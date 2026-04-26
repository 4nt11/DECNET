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
