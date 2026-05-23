# SPDX-License-Identifier: AGPL-3.0-or-later
"""R0031-R0040 — behavioral / cross-event cohort.

Every rule here is consumed by the :class:`BehavioralLifter` (E.3.9).
The v0 :class:`RuleEngine` has no counter / aggregator — it can only
regex over a single event payload — so these rules cannot fire from
the engine alone. Their ``match.kind`` prefix ``lifter:behavioral_``
is inert to the regex matcher by design.

This file asserts:

* every R003N has a YAML on disk that compiles
* the v0 engine NEVER fires any of them (regression guard against a
  YAML drifting into a regex match)
* the lifter achieves the per-rule precision target on the labelled
  corpus.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest

from decnet.ttp.impl.behavioral_lifter import BehavioralLifter
from decnet.ttp.impl.rule_engine import RuleEngine
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.filesystem import _parse_and_compile
from tests.ttp._stub_store import StubRuleStore
from tests.ttp.rule_precision.conftest import (
    CorpusRow,
    make_event,
    precision_for,
)

CohortLoader = Callable[[str], list[CorpusRow]]

_RULE_IDS = [f"R{n:04d}" for n in range(31, 41)]


@pytest.mark.parametrize("rule_id", _RULE_IDS)
def test_rule_yaml_present(rule_id: str) -> None:
    path = Path("rules/ttp") / f"{rule_id}.yaml"
    assert path.exists(), f"missing YAML: {path}"
    compiled = _parse_and_compile(path, RuleState())
    assert compiled.rule_id == rule_id


@pytest.mark.parametrize("rule_id", _RULE_IDS)
async def test_lifter_bound_inert_in_v0(
    rule_id: str,
    precision_engine: RuleEngine,
    corpus_loader: CohortLoader,
) -> None:
    """Behavioral rules MUST NOT fire from the regex engine.

    Walks both the behavioral and the command corpora — if any event
    in either set lights up a behavioral rule, a YAML drifted into a
    regex match.spec.
    """
    fired: set[str] = set()
    for cohort in ("behavioral", "commands"):
        for row in corpus_loader(cohort):
            tags = await precision_engine.evaluate(make_event(row))
            fired.update(tag.rule_id for tag in tags)
    assert rule_id not in fired, (
        f"{rule_id} is lifter-bound but fired from the regex engine"
    )


def _all_rule_ids() -> list[str]:
    return _RULE_IDS


def _build_lifter() -> BehavioralLifter:
    rules_dir = Path("rules/ttp")
    rules = [
        _parse_and_compile(rules_dir / f"{rid}.yaml", RuleState())
        for rid in _all_rule_ids()
    ]
    lifter = BehavioralLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


@pytest.mark.parametrize("rule_id", _RULE_IDS)
def test_behavioral_rule_precision(
    rule_id: str,
    corpus_loader: CohortLoader,
) -> None:
    """Drive the lifter over the behavioral corpus and assert precision.

    H-band (≥0.85 confidence) → ≥95% precision. v0 ships with a small
    synthetic seed corpus; precision_for() returns 1.0 when no rows
    match, so the assertion exercises the FP-guard rather than the
    recall property (recall is intentionally not a v1 target — see
    TTP_TAGGING.md Appendix C).
    """
    rows = corpus_loader("behavioral")
    if not rows:
        pytest.skip("no behavioral corpus available")
    lifter = _build_lifter()
    fired: dict[str, list[str]] = {}
    for row in rows:
        tags = asyncio.run(lifter.tag(make_event(row)))
        fired[row.label] = [tag.rule_id for tag in tags]
    precision, _tp, _fp = precision_for(rule_id, rows, fired)
    assert precision >= 0.95, (
        f"{rule_id} precision {precision:.2f} < 0.95 on behavioral corpus"
    )
