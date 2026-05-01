"""R0041-R0048 — email cohort.

EmailLifter (E.3.12) consumes these by rule_id. The v0
:class:`RuleEngine` cannot parse SMTP envelopes, walk attachment
trees, or compose header / body / attachment signals — so these
rules are inert under the regex matcher.

Asserts each YAML compiles, none fire from the v0 engine, and a
strict-xfail precision case that flips green when E.3.12 lands.
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

_RULE_IDS = [f"R{n:04d}" for n in range(41, 49)]


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
    fired: set[str] = set()
    for row in corpus_loader("email"):
        tags = await precision_engine.evaluate(make_event(row))
        fired.update(tag.rule_id for tag in tags)
    assert rule_id not in fired, (
        f"{rule_id} is lifter-bound but fired from the regex engine"
    )


@pytest.mark.parametrize("rule_id", _RULE_IDS)
@pytest.mark.xfail(strict=True, reason="impl phase E.3.12 (EmailLifter)")
def test_email_rule_precision(rule_id: str) -> None:
    pytest.fail(f"{rule_id}: EmailLifter not yet shipped (E.3.12)")
