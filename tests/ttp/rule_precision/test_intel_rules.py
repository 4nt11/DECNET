"""R0054-R0058 — intel verdict cohort.

IntelLifter (E.3.10) reads ``AttackerIntel`` provider columns
(AbuseIPDB, GreyNoise, Feodo, ThreatFox) and emits per the per-
provider mapping tables in Appendix A.10. Per Appendix B every
intel rule tolerates absence silently — a null provider column is
"no tag from this rule", never an error. R0058 is the
confidence-bump-only meta-rule (no fresh tag emission); the
lifter inspects rule_id and bumps existing tags.

The v0 :class:`RuleEngine` cannot navigate the intel envelope —
the rules are inert under regex.
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

_RULE_IDS = [f"R{n:04d}" for n in range(54, 59)]


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
    for row in corpus_loader("intel"):
        tags = await precision_engine.evaluate(make_event(row))
        fired.update(tag.rule_id for tag in tags)
    assert rule_id not in fired


def test_r0058_is_bump_only() -> None:
    """R0058's only emit is a zero-confidence sentinel.

    Per Appendix B the aggregate-malicious rule must not emit a fresh
    tag — it bumps existing rule confidences. The repository drops
    tags below 0.3 confidence, so even if the lifter accidentally
    drove the engine fanout the tag would never persist. This test
    pins that defense-in-depth property: any future edit pushing the
    R0058 emit confidence above 0 would fire here.
    """
    compiled = _parse_and_compile(
        Path("rules/ttp/R0058.yaml"), RuleState(),
    )
    assert all(emit[3] == 0.0 for emit in compiled.emits), (
        "R0058 must keep all emit confidences at 0.0 (bump-only rule)"
    )


@pytest.mark.parametrize("rule_id", _RULE_IDS)
@pytest.mark.xfail(strict=True, reason="impl phase E.3.10 (IntelLifter)")
def test_intel_rule_precision(rule_id: str) -> None:
    pytest.fail(f"{rule_id}: IntelLifter not yet shipped (E.3.10)")
