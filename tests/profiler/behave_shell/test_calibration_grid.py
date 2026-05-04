"""Step 9: calibration grid lockdown — the Phase A gate.

Runs the **pure engine** (``behave_shell.extract_session()``) against
each of the five 2026-05-02 calibration shards. The shards live in
``BEHAVE/prototype_extractors/shell/`` and are gitignored — fixture
path is resolved via the ``BEHAVE_CALIBRATION_DIR`` env var; the test
is skipped if that var is unset (CI provides it; local dev doesn't
have to).

The hard gate that this commit pins (and that all subsequent Phase
B-G PRs must keep green): each shard must emit every Phase A
primitive at least once across its sessions. Engine is allowed to
emit *more* than required.

Per-class expected values (the calibration **target**, not a hard
gate yet — value-level pins land once cross-class thresholds are
re-tuned with a wider corpus) are pinned in a softer cross-class
discrimination check below.
"""
from __future__ import annotations

import collections
import json
import os
from pathlib import Path
from typing import Any

import pytest

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import parse_shard_line


PHASE_AB_PRIMITIVES: frozenset[str] = frozenset({
    # Phase A — calibration floor
    "motor.input_modality",
    "motor.paste_burst_rate",
    "cognitive.inter_command_latency_class",
    "cognitive.command_branch_diversity",
    "cognitive.feedback_loop_engagement",
    "cognitive.inter_command_consistency",
    # Phase B — motor.* completion (lands one primitive per commit)
    "motor.keystroke_cadence",
    "motor.motor_stability",
    "motor.error_correction",
})


# (shard filename, class label)
SHARDS: list[tuple[str, str]] = [
    ("sessions-2026-05-02.jsonl",                "HUMAN"),
    ("sessions-2026-05-02-with-llm.jsonl",       "YOU-sim"),
    ("sessions-2026-05-02-new.jsonl",            "LW-sim"),
    ("sessions-2026-05-02-with-claude.jsonl",    "CLAUDE-FF"),
    ("sessions-2026-05-02-closed-loop.jsonl",    "CLAUDE-CL"),
]


def _calibration_dir() -> Path | None:
    raw = os.environ.get("BEHAVE_CALIBRATION_DIR")
    if not raw:
        return None
    p = Path(raw).expanduser()
    return p if p.is_dir() else None


@pytest.fixture(scope="module")
def calibration_dir() -> Path:
    d = _calibration_dir()
    if d is None:
        pytest.skip("BEHAVE_CALIBRATION_DIR unset or not a directory")
    return d


def _sessions_in_shard(path: Path) -> dict[str, list[Any]]:
    """Group raw events by sid, skipping headers and junk."""
    by_sid: dict[str, list[Any]] = collections.defaultdict(list)
    with path.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            sid = rec.get("sid") if isinstance(rec, dict) else None
            if not sid or "hdr" in rec:
                continue
            ev = parse_shard_line(line)
            if ev is not None:
                by_sid[sid].append(ev)
    return by_sid


def _all_observations(path: Path) -> list:
    obs: list = []
    for sid, events in _sessions_in_shard(path).items():
        obs.extend(extract_session(events, sid=sid))
    return obs


@pytest.mark.parametrize("shard_file,class_label", SHARDS, ids=[c for _, c in SHARDS])
def test_shard_emits_all_phase_a_primitives(
    shard_file: str,
    class_label: str,
    calibration_dir: Path,
) -> None:
    """Hard gate: every Phase A primitive fires at least once per shard."""
    path = calibration_dir / shard_file
    if not path.is_file():
        pytest.skip(f"shard not present at {path}")
    obs = _all_observations(path)
    assert obs, f"{class_label}: extractor produced zero observations"
    seen = {o.primitive for o in obs}
    missing = PHASE_AB_PRIMITIVES - seen
    assert not missing, (
        f"{class_label} ({shard_file}) missing primitives: "
        f"{sorted(missing)}"
    )


def test_shards_are_discriminative_across_classes(
    calibration_dir: Path,
) -> None:
    """Smoke discrimination: at least one Phase A primitive must
    show different majority values across classes.

    A constant-output engine (every shard yields the same value for
    every primitive) would fail this check — that's the regression we
    care about. Tighter per-class value pinning lands as the corpus
    grows.
    """
    by_class: dict[str, dict[str, str]] = {}
    for shard_file, label in SHARDS:
        path = calibration_dir / shard_file
        if not path.is_file():
            continue
        per_prim: dict[str, collections.Counter] = collections.defaultdict(
            collections.Counter
        )
        for o in _all_observations(path):
            per_prim[o.primitive][str(o.value)] += 1
        by_class[label] = {
            prim: ctr.most_common(1)[0][0] for prim, ctr in per_prim.items()
        }
    if len(by_class) < 2:
        pytest.skip("need at least two shards present to compare")

    # At least one primitive should produce different majority values
    # across the present classes.
    discriminative_primitives: list[str] = []
    for prim in PHASE_AB_PRIMITIVES:
        values = {by_class[c].get(prim) for c in by_class if prim in by_class[c]}
        if len(values) >= 2:
            discriminative_primitives.append(prim)
    assert discriminative_primitives, (
        f"Engine emitted identical majority values for every Phase A "
        f"primitive across {sorted(by_class)} — likely a constant-output "
        f"regression. Class summaries: {by_class}"
    )
