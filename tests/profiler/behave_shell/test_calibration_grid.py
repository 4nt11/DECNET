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


PHASE_ABCDEFG_PRIMITIVES: frozenset[str] = frozenset({
    # Phase A — calibration floor
    "motor.input_modality",
    "motor.paste_burst_rate",
    "cognitive.inter_command_latency_class",
    "cognitive.command_branch_diversity",
    "cognitive.feedback_loop_engagement",
    "cognitive.inter_command_consistency",
    # Phase B — motor.* completion
    "motor.keystroke_cadence",
    "motor.motor_stability",
    "motor.error_correction",
    "motor.command_chunking",
    # Phase C — motor.shell_mastery.*
    "motor.shell_mastery.tab_completion",
    "motor.shell_mastery.shortcut_usage",
    "motor.shell_mastery.pipe_chaining_depth",
    # Phase D — cognitive.* completion (error_resilience.* are
    # conditional, see PHASE_D_CONDITIONAL_PRIMITIVES below)
    "cognitive.cognitive_load",
    "cognitive.exploration_style",
    "cognitive.planning_depth",
    "cognitive.tool_vocabulary",
    # Phase E — temporal.* per-session subset
    "temporal.session_duration",
    "temporal.escalation_pattern",
    "temporal.lifecycle_markers.landing_ritual",
    # Phase F — environmental.* output-stream block + carry-over E.4
    # (locale and keyboard_layout are conditional — see
    # PHASE_F_CONDITIONAL_PRIMITIVES)
    "environmental.shell_type",
    "environmental.terminal_multiplexer",
    "environmental.numpad_usage",
    "temporal.lifecycle_markers.exit_behavior",
    # Phase G — operational.* + emotional_valence.* (hard subset)
    # The rest of Phase G are gated by sample-size floors and ride in
    # PHASE_G_CONDITIONAL_PRIMITIVES below (objective needs classified
    # commands, multi_actor needs ≥ 8 commands, arousal needs typing
    # bursts, valence / frustration_venting need typed-letter floors).
    "operational.opsec_discipline",
    "operational.cleanup_behavior",
    "emotional_valence.stress_response",
})

# Phase D primitives that are conditional on at least one errored
# command in the shard. These widen the universe the calibration grid
# *checks* for discriminative output but don't force every shard to
# emit them.
PHASE_D_CONDITIONAL_PRIMITIVES: frozenset[str] = frozenset({
    "cognitive.error_resilience.retry_tactic",
    "cognitive.error_resilience.frustration_typing",
    "cognitive.error_resilience.fallback_to_man",
})

# Phase F primitives conditional on shard content.
# * ``environmental.locale`` fires only when the shard's output contains
#   an env / locale dump (LANG=, LC_ALL=, LC_CTYPE=).
# * ``environmental.keyboard_layout`` requires LAYOUT_MIN_TYPED_LETTERS
#   (200) typed letters per session — short SSH-recon shards (the
#   2026-05-02 calibration corpus) max out around 90 typed letters
#   per session because most input is pasted rather than typed.
#   v0 keeps the 200-floor honesty rather than tuning to pass; longer-
#   text corpora will surface it.
PHASE_F_CONDITIONAL_PRIMITIVES: frozenset[str] = frozenset({
    "environmental.locale",
    "environmental.keyboard_layout",
})

# Phase G primitives that ride sample-size floors and may legitimately
# skip emission on shards that don't meet them. Tracked for grid
# discrimination but not part of the per-shard hard gate.
PHASE_G_CONDITIONAL_PRIMITIVES: frozenset[str] = frozenset({
    "operational.objective",                # needs ≥ 3 classified commands
    "operational.multi_actor_indicators",   # needs ≥ 8 commands
    "emotional_valence.arousal",            # needs typing bursts
    "emotional_valence.valence",            # needs ≥ 80 typed letters
    "emotional_valence.frustration_venting",  # needs ≥ 30 typed letters
})

# Backwards-compatible aliases for any external import — earlier phases
# locked in narrower sets; later phases widen them. All names point at
# the current binding set.
PHASE_ABCDEF_PRIMITIVES = PHASE_ABCDEFG_PRIMITIVES
PHASE_ABCDE_PRIMITIVES = PHASE_ABCDEFG_PRIMITIVES
PHASE_ABCD_PRIMITIVES = PHASE_ABCDEFG_PRIMITIVES
PHASE_ABC_PRIMITIVES = PHASE_ABCDEFG_PRIMITIVES


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
    missing = PHASE_ABCDEFG_PRIMITIVES - seen
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
    for prim in PHASE_ABCDEFG_PRIMITIVES:
        values = {by_class[c].get(prim) for c in by_class if prim in by_class[c]}
        if len(values) >= 2:
            discriminative_primitives.append(prim)
    assert discriminative_primitives, (
        f"Engine emitted identical majority values for every Phase A "
        f"primitive across {sorted(by_class)} — likely a constant-output "
        f"regression. Class summaries: {by_class}"
    )
