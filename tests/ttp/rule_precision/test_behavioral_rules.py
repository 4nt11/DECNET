"""R0031-R0040 — behavioral / cross-event cohort.

Every rule here is consumed by the BehavioralLifter (or an
identity-rollup variant) at E.3.9. The v0 :class:`RuleEngine` has no
counter / aggregator — it can only regex over a single event
payload — so these rules cannot fire from the engine alone. Their
``match.kind`` keys (``lifter:beaconing`` etc.) are inert to the
regex matcher by design.

This file asserts:

* every R003N has a YAML on disk that compiles
* the v0 engine NEVER fires any of them (regression guard against a
  YAML drifting into a regex match)
* the precision target test is :pyfunc:`pytest.xfail`-gated until
  the BehavioralLifter ships, matching the CDD pattern at
  ``development/TTP_TAGGING.md:2450``.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from decnet.ttp.impl.rule_engine import RuleEngine
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.filesystem import _parse_and_compile
from tests.ttp.rule_precision.conftest import CorpusRow, make_event

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


@pytest.mark.parametrize("rule_id", _RULE_IDS)
@pytest.mark.xfail(strict=True, reason="impl phase E.3.9 (BehavioralLifter)")
def test_behavioral_rule_precision(rule_id: str) -> None:
    """Will live once the BehavioralLifter ships at E.3.9.

    The lifter consumes ``AttackerBehavior`` / session aggregates and
    emits one tag per matching rule_id. This test will then load the
    behavioral corpus, drive the lifter, and assert the per-rule
    precision target. Until that day this xfails strict so the suite
    flips green automatically when E.3.9 wires it up.
    """
    pytest.fail(f"{rule_id}: BehavioralLifter not yet shipped (E.3.9)")
