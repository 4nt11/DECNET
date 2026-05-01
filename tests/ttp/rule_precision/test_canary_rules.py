"""R0049-R0053 — canary fingerprint cohort.

CanaryFingerprintLifter (E.3.11) parses the fingerprint payload
(navigator/webdriver flag, canvas/audio/WebGL hashes, WebRTC IPs,
TZ/language/geo composite) and emits per Appendix A.9. The v0
:class:`RuleEngine` cannot navigate a structured fingerprint blob —
these rules are inert under the regex matcher.
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

_RULE_IDS = [f"R{n:04d}" for n in range(49, 54)]


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
    for row in corpus_loader("canary"):
        tags = await precision_engine.evaluate(make_event(row))
        fired.update(tag.rule_id for tag in tags)
    assert rule_id not in fired


@pytest.mark.parametrize("rule_id", _RULE_IDS)
@pytest.mark.xfail(
    strict=True, reason="impl phase E.3.11 (CanaryFingerprintLifter)",
)
def test_canary_rule_precision(rule_id: str) -> None:
    pytest.fail(f"{rule_id}: CanaryFingerprintLifter not yet shipped (E.3.11)")
