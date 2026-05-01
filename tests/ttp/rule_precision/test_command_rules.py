"""Per-rule precision asserts for the command cohort (R0001-R0030).

Drives the labelled corpus through a real :class:`RuleEngine` populated
from ``./rules/ttp/`` and asserts each rule meets its Appendix-C
precision target.

Live vs xfail per rule:

* R0001-R0006 / R0030: lifter-bound (auth-attempt aggregation, identity
  rollups, fingerprint blob parsing). v0 :class:`RuleEngine` only does
  regex-on-payload-field, so these can never fire from the engine
  alone. Their precision tests are :pyfunc:`pytest.xfail` until the
  matching lifter ships (E.3.9 / E.3.13).
* R0007-R0029: regex-driven on ``command_text`` / ``raw_url`` / ``user_agent``.
  Live precision asserts against the seed corpus (committed) and any
  operator-built ``commands.jsonl`` (gitignored, preferred).

Precision target per Appendix C: ≥0.95 for high-conf rules
(base ``confidence >= 0.85``), ≥0.80 for medium (0.6-0.85). The
fixture's :func:`precision_for` returns 1.0 vacuously when no rows
fired the rule — :func:`pytest.skip` covers that case so a sparse
corpus skips loudly rather than silently passing.
"""
from __future__ import annotations

from collections.abc import Callable

import pytest

from decnet.ttp.impl.rule_engine import RuleEngine
from tests.ttp.rule_precision.conftest import (
    CorpusRow,
    make_event,
    precision_for,
)

CohortLoader = Callable[[str], list[CorpusRow]]

# Lifter-bound rules: cannot fire from the v0 engine.
_LIFTER_BOUND: dict[str, str] = {
    "R0001": "impl phase E.3.9 (BehavioralLifter — auth brute count)",
    "R0002": "impl phase E.3.9 (BehavioralLifter — password guessing)",
    "R0003": "impl phase E.3.13 (IdentityLifter — password spraying)",
    "R0004": "impl phase E.3.13 (CredentialLifter — credential reuse)",
    "R0005": "impl phase E.3.9 (BehavioralLifter — valid account use)",
    "R0006": "impl phase E.3.9 (BehavioralLifter — default creds)",
    "R0030": "impl phase E.3.9 (BehavioralLifter — JARM/HASSH match)",
}

# Per-rule precision floor. Anything ≥0.85 base confidence in the YAML
# is "high"; 0.6-0.85 is "medium". Sub-0.6 is not shipped in v0.
_PRECISION_TARGET: dict[str, float] = {
    "R0007": 0.95, "R0008": 0.95, "R0009": 0.95, "R0010": 0.95,
    "R0011": 0.80, "R0012": 0.95, "R0013": 0.95, "R0014": 0.95,
    "R0015": 0.95, "R0016": 0.80, "R0017": 0.95, "R0018": 0.80,
    "R0019": 0.80, "R0020": 0.80, "R0021": 0.80, "R0022": 0.95,
    "R0023": 0.95, "R0024": 0.95, "R0025": 0.95, "R0026": 0.95,
    "R0027": 0.95, "R0028": 0.95, "R0029": 0.80,
}

_ALL_RULE_IDS = [f"R{n:04d}" for n in range(1, 31)]


@pytest.fixture(scope="module")
def fired_by_label(
    precision_engine: RuleEngine,
    corpus_loader: CohortLoader,
) -> tuple[dict[str, list[str]], list[CorpusRow]]:
    """Pre-evaluate the corpus once per module.

    Returns ``(label → [rule_ids that fired], rows)``. Each rule's
    test then walks the same dict — saves 30× re-evaluation.
    """
    rows = corpus_loader("commands")
    fired: dict[str, list[str]] = {}
    import asyncio

    async def _drive() -> None:
        for row in rows:
            tags = await precision_engine.evaluate(make_event(row, source_id=row.label))
            fired[row.label] = sorted({tag.rule_id for tag in tags})

    asyncio.run(_drive())
    return fired, rows


@pytest.mark.parametrize("rule_id", _ALL_RULE_IDS)
def test_rule_yaml_present(rule_id: str) -> None:
    """Every R000N rule_id has a YAML on disk that compiles.

    Catches a missing or malformed file faster than the precision
    test would (the latter would just see zero matches).
    """
    from pathlib import Path

    from decnet.ttp.store.base import RuleState
    from decnet.ttp.store.impl.filesystem import _parse_and_compile

    path = Path("rules/ttp") / f"{rule_id}.yaml"
    assert path.exists(), f"missing YAML: {path}"
    compiled = _parse_and_compile(path, RuleState())
    assert compiled.rule_id == rule_id


@pytest.mark.parametrize("rule_id", list(_LIFTER_BOUND))
def test_lifter_bound_rule_inert_in_v0(
    rule_id: str,
    fired_by_label: tuple[dict[str, list[str]], list[CorpusRow]],
) -> None:
    """Lifter-bound rules MUST NOT fire from the v0 engine.

    They're carried in ``./rules/ttp/`` so the catalogue surfaces
    them and the lifter can read them by rule_id, but the regex
    engine can't interpret a ``match.kind: lifter:*`` spec — it
    falls into the ``pattern is None`` branch and silently skips.
    A regression that lit one of these up from regex would mean a
    YAML drifted into a ``pattern:`` form and we'd be emitting
    half-baked tags.
    """
    fired, _rows = fired_by_label
    matches = [label for label, ids in fired.items() if rule_id in ids]
    assert matches == [], (
        f"{rule_id} is lifter-bound but fired on: {matches}"
    )


@pytest.mark.parametrize("rule_id", list(_PRECISION_TARGET))
def test_command_rule_precision(
    rule_id: str,
    fired_by_label: tuple[dict[str, list[str]], list[CorpusRow]],
) -> None:
    """Each live regex rule meets its Appendix-C precision target."""
    fired, rows = fired_by_label
    matched = sum(1 for ids in fired.values() if rule_id in ids)
    if matched == 0:
        pytest.skip(
            f"{rule_id}: no corpus rows matched — extend "
            "tests/ttp/rule_precision/corpus/seed_commands.jsonl",
        )
    target = _PRECISION_TARGET[rule_id]
    precision, tp, fp = precision_for(rule_id, rows, fired)
    assert precision >= target, (
        f"{rule_id} precision {precision:.2f} < target {target:.2f} "
        f"(tp={tp} fp={fp})"
    )
