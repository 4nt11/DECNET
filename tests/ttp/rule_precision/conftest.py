"""Fixtures for the per-rule precision suite.

Two halves:

* :func:`precision_engine` — async fixture that builds a real
  :class:`RuleEngine` populated from ``./rules/ttp/`` via
  :func:`_parse_and_compile`. We bypass ``RuleEngine.watch_store``
  (which would loop forever on the inotify subscription) and instead
  call ``_install`` directly per rule. The engine reads no rules
  through any store ABC method, so a stub store passes for
  construction.
* :func:`corpus_loader` — factory fixture returning labelled rows
  for a cohort (``commands`` / ``email`` / ``intel`` / ``canary`` /
  ``behavioral``). Prefers ``corpus/<name>.jsonl`` (operator-built,
  gitignored) and falls back to ``corpus/seed_<name>.jsonl``
  (synthetic, committed). If neither exists the fixture returns ``[]``
  and the precision tests :func:`pytest.skip` themselves — letting a
  fresh checkout exercise the harness without a corpus.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import pytest_asyncio

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.rule_engine import CompiledRule, RuleEngine
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.filesystem import _parse_and_compile

_RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "ttp"
_CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


class CorpusRow(NamedTuple):
    """One labelled corpus row.

    ``payload`` carries the keys the engine's match operator reads —
    ``command_text`` for ``command``, ``raw_url`` for ``http_request``,
    etc. ``expected_rule_ids`` is the human-labelled ground truth: the
    rules a competent analyst would expect to fire on this row.
    Negative examples (``[]``) are load-bearing for precision: they
    catch FPs by giving non-matching payloads in the "matches" pool.
    """

    source_kind: str
    payload: dict[str, Any]
    expected_rule_ids: tuple[str, ...]
    label: str


class _StubStore:
    """Just enough of :class:`RuleStore` to satisfy ``RuleEngine.__init__``.

    The fixture installs rules directly into the engine's dispatch
    index; no store method is actually called during precision tests.
    """

    async def load_compiled(self) -> list[CompiledRule]:
        return []

    async def get_state(self, _rule_id: str) -> RuleState:
        return RuleState()

    async def set_state(self, *_a: Any, **_kw: Any) -> None:
        return None

    def subscribe_changes(self) -> Any:
        async def _gen() -> Any:
            if False:  # pragma: no cover
                yield None
        return _gen()


def _load_compiled_rules() -> list[CompiledRule]:
    """Compile every YAML under ``./rules/ttp/`` once per session.

    Ignores files that fail to parse — the cohort tests assert presence
    of their rule_id, so a bad YAML surfaces as a missing-rule failure
    rather than a confusing ImportError out of the fixture.
    """
    if not _RULES_DIR.exists():
        return []
    out: list[CompiledRule] = []
    state = RuleState()
    for path in sorted(_RULES_DIR.iterdir()):
        if path.suffix not in {".yaml", ".yml"}:
            continue
        try:
            out.append(_parse_and_compile(path, state))
        except Exception:  # noqa: BLE001 — broken YAML is its own failure surface
            continue
    return out


@pytest.fixture(scope="session")
def compiled_rules() -> list[CompiledRule]:
    return _load_compiled_rules()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def precision_engine(
    compiled_rules: list[CompiledRule],
) -> RuleEngine:
    """A :class:`RuleEngine` with every YAML rule installed.

    Bypasses ``watch_store()`` (it loops forever on the inotify
    subscription). The engine's public ``evaluate()`` reads only
    ``self._by_kind`` / ``self._by_rule``, both populated here.
    """
    engine = RuleEngine(_StubStore())  # type: ignore[arg-type]
    for rule in compiled_rules:
        engine._install(rule)
    return engine


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            rows.append(json.loads(stripped))
    return rows


def _resolve_corpus_path(name: str) -> Path | None:
    real = _CORPUS_DIR / f"{name}.jsonl"
    if real.exists():
        return real
    seed = _CORPUS_DIR / f"seed_{name}.jsonl"
    if seed.exists():
        return seed
    return None


def _row_from_dict(raw: dict[str, Any]) -> CorpusRow:
    return CorpusRow(
        source_kind=str(raw.get("source_kind", "command")),
        payload=dict(raw.get("payload", {})),
        expected_rule_ids=tuple(raw.get("expected_rule_ids", [])),
        label=str(raw.get("label", "")),
    )


@pytest.fixture(scope="session")
def corpus_loader() -> Callable[[str], list[CorpusRow]]:
    """Return a callable that loads a cohort's labelled corpus.

    Resolution order: ``corpus/<name>.jsonl`` (real, gitignored) →
    ``corpus/seed_<name>.jsonl`` (synthetic, committed) → empty list
    (caller's tests skip).
    """

    def _load(name: str) -> list[CorpusRow]:
        path = _resolve_corpus_path(name)
        if path is None:
            return []
        return [_row_from_dict(row) for row in _read_jsonl(path)]

    return _load


def make_event(row: CorpusRow, source_id: str = "src") -> TaggerEvent:
    """Materialise a :class:`CorpusRow` into a :class:`TaggerEvent`.

    Sets a deterministic ``attacker_uuid`` derived from the row label so
    the downstream ``TTPTag`` constructor's "at least one of
    attacker_uuid/identity_uuid" invariant is satisfied. The corpus
    rows themselves don't carry attacker identity — they're per-payload
    fixtures, not per-attacker — so this synthesis is purely a test
    plumbing concern.
    """
    return TaggerEvent(
        source_kind=row.source_kind,
        source_id=source_id,
        attacker_uuid=f"corpus-{row.label}",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload=row.payload,
    )


def precision_for(
    rule_id: str,
    rows: list[CorpusRow],
    fired: dict[str, list[str]],
) -> tuple[float, int, int]:
    """Compute precision = TP / (TP + FP) for *rule_id*.

    ``fired[label] = [rule_ids that matched this row]``. A row whose
    ``expected_rule_ids`` includes *rule_id* and whose match set
    includes *rule_id* is a TP. A row that fired *rule_id* but did
    NOT expect it is a FP.

    Returns ``(precision, tp, fp)``. Precision is ``1.0`` when no
    matches fired (vacuously) — callers gate that case with the
    ``min_matches`` check before asserting.
    """
    tp = 0
    fp = 0
    for row in rows:
        matched = rule_id in fired.get(row.label, [])
        expected = rule_id in row.expected_rule_ids
        if matched and expected:
            tp += 1
        elif matched and not expected:
            fp += 1
    total = tp + fp
    if total == 0:
        return 1.0, 0, 0
    return tp / total, tp, fp


__all__ = [
    "CorpusRow",
    "compiled_rules",
    "precision_engine",
    "corpus_loader",
    "make_event",
    "precision_for",
]
