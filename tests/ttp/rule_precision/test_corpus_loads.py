# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sentinel: every cohort's seed corpus parses and the harness lives.

Runs in clean checkouts (no operator-built corpus). Asserts the seed
JSONL files load through :func:`corpus_loader` without raising and
yield non-empty lists. Doesn't run any rules — that's the per-cohort
suites' job. This sentinel exists so a busted corpus file fails the
suite immediately, not three commits later when the first cohort
test finally tries to load it.
"""
from __future__ import annotations

from collections.abc import Callable

import pytest

from tests.ttp.rule_precision.conftest import CorpusRow

CohortLoader = Callable[[str], list[CorpusRow]]


@pytest.mark.parametrize(
    "name",
    ["commands", "email", "intel", "canary", "behavioral"],
)
def test_seed_corpus_loads(
    corpus_loader: CohortLoader, name: str,
) -> None:
    rows = corpus_loader(name)
    assert rows, f"seed_{name}.jsonl returned no rows"
    for row in rows:
        assert row.source_kind, f"row {row.label} missing source_kind"
        assert isinstance(row.payload, dict)
        assert isinstance(row.expected_rule_ids, tuple)
