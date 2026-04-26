"""
Shared helpers for fixture-driven clustering tests.

Each fixture lives at `tests/fixtures/campaigns/<name>.yaml` with paired
`<name>.expected.yaml` bound file. The harness here keeps every per-
fixture test file down to "load corpus → predict → assert bounds" without
copy-pasting the bound-walk loop or reference clusterers across files.

Two reference clusterers are provided:

* `identity_clusterer` — every attacker is its own cluster. Trivially
  passes any fixture whose ground truth is all singletons (lone_wolf,
  shared_wordlist before merge, etc). Useful as a green baseline while
  the real connected-components algorithm is under construction.

* `credential_jaccard_clusterer` — deliberately-bad reference that
  merges any two attackers whose credential-attempt sets overlap above
  a threshold. Exists so fixtures like `shared_wordlist` can prove
  they fail a clusterer that relies on credential overlap alone — the
  whole point of fixture #1.
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
) -> dict[str, float]:
    """
    Run `predict` against the corpus, score against ground truth, and
    assert every metric meets the floor declared in `expected_path`.

    Returns the observed metrics dict so callers can do additional
    assertions (e.g. "homogeneity is *exactly* 1.0 for this fixture").
    """
    bounds = yaml.safe_load(Path(expected_path).read_text(encoding="utf-8"))
    truth = corpus.truth_labels()
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
