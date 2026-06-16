# SPDX-License-Identifier: AGPL-3.0-or-later
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


def _build_lifter() -> "EmailLifter":
    from decnet.ttp.impl.email_lifter import EmailLifter
    from tests.ttp._stub_store import StubRuleStore

    rules = [
        _parse_and_compile(Path("rules/ttp") / f"{rid}.yaml", RuleState())
        for rid in _RULE_IDS
    ]
    lifter = EmailLifter(StubRuleStore(compiled=rules))
    for rule in rules:
        lifter._index.install(rule)
    return lifter


@pytest.mark.parametrize("rule_id", _RULE_IDS)
def test_email_rule_precision(
    rule_id: str,
    corpus_loader: CohortLoader,
) -> None:
    """E.3.12 — drive EmailLifter over the labelled corpus and assert
    per-rule precision. R0041–R0048 are all H-band (≥0.85) → ≥95%.
    """
    import asyncio

    from tests.ttp.rule_precision.conftest import precision_for

    rows = corpus_loader("email")
    if not rows:
        pytest.skip("no email corpus available")
    lifter = _build_lifter()
    fired: dict[str, list[str]] = {}
    for row in rows:
        tags = asyncio.run(lifter.tag(make_event(row)))
        fired[row.label] = [tag.rule_id for tag in tags]
    precision, _tp, _fp = precision_for(rule_id, rows, fired)
    assert precision >= 0.95, (
        f"{rule_id} precision {precision:.2f} < 0.95 on email corpus"
    )
