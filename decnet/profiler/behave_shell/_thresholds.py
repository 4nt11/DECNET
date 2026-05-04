"""Numeric thresholds for BEHAVE-SHELL primitive classification.

Each constant cites its calibration source. When the registry's
``notes:`` field disagrees with a constant here, the registry is
authoritative — fix the constant, re-run the calibration grid.

Empirical thresholds inherited from the BEHAVE prototype extractor
(``BEHAVE/prototype_extractors/shell/extract.py``); see lines 40-90 of
that file for the calibration history. Any change here must keep the
five-class grid green.
"""
from __future__ import annotations

# ── paste-burst detection (Step 1) ──────────────────────────────────────────
# A single input event with ≥ PASTE_MIN_CHARS_PER_EVENT chars is the
# paste-class proxy used by the prototype; xterm-kitty / iTerm / VS Code
# pastes arrive as one bulk write.
PASTE_MIN_CHARS_PER_EVENT: int = 4

# Consecutive paste-class events arriving within this IAT collapse into
# one PasteBurst record. 200ms is the prototype's IKI burst cap.
PASTE_BURST_MAX_IAT_S: float = 0.20

# ── motor.input_modality (Step 2) ───────────────────────────────────────────
# Paste-event ratio thresholds. ≥ 40% paste events → "pasted" (LLM-driven);
# ≤ 5% → "typed" (human at the keyboard); in between → "mixed".
# Lowered from 0.5 after the 47.6% case in sessions-2026-05-02-with-llm.jsonl
# was clearly LLM-driven but missed the 0.5 floor.
MODALITY_PASTED_MIN: float = 0.40
MODALITY_TYPED_MAX: float = 0.05

# ── motor.paste_burst_rate (Step 3) ─────────────────────────────────────────
# Same paste-event ratio re-bucketed for the "how often does the operator
# paste" axis. Coarser than input_modality on purpose: this primitive is the
# habit signal, input_modality is the dominant-channel signal.
PASTE_RATE_HABITUAL_MIN: float = 0.50
PASTE_RATE_OCCASIONAL_MIN: float = 0.10

# ── cognitive.inter_command_latency_class (Step 5) ──────────────────────────
# Bucket edges (seconds) for the median inter-command IAT. Prototype
# values; v0.2 splits the original llm_roundtrip 2-8s band into
# llm_lightweight (orchestrated agents w/ small models / terse prompts) and
# llm_heavyweight (reasoning-class agents in tool loops with text
# generation between calls). Empirical anchor: Claude Opus driving recon
# via tmux send-keys produced a median of 15.5s.
INTER_CMD_INSTANT_MAX: float = 0.30
INTER_CMD_TYPING_MAX: float = 1.50
INTER_CMD_DELIBERATE_MAX: float = 2.00
INTER_CMD_LLM_LIGHTWEIGHT_MAX: float = 8.00
INTER_CMD_LLM_HEAVYWEIGHT_MAX: float = 30.00

# Sample-size floor for inter-command IAT primitives. Below this we
# halve the confidence per BEHAVE-EXTRACTOR.md "sample-size honesty".
MIN_COMMANDS_FOR_FULL_CONFIDENCE: int = 5

# ── cognitive.command_branch_diversity (Step 6) ─────────────────────────────
# unique_first_tokens / total_commands ratio. Prototype's empirical
# split (sessions-2026-05-02-* corpus): CLAUDE-CL chasing one finding
# ≈ 0.55-0.60 (adaptive), HUMAN exploring filesystem ≈ 0.65-0.70
# (adaptive), YOU-sim / CLAUDE-FF scripted recon ≈ 0.75+ (linear).
BRANCH_DIVERSITY_LINEAR_MIN: float = 0.70   # >= → linear_playbook

# ── cognitive.feedback_loop_engagement (Step 7) ─────────────────────────────
# Pearson r threshold for "the operator's pause grew with the volume of
# preceding output". |r| > this → significant; sign carries direction.
FEEDBACK_CORRELATION_MIN: float = 0.30
# Need at least this many (output_bytes, next_pause) pairs to even
# attempt a correlation. Below this the answer is "unknown".
FEEDBACK_MIN_PAIRS: int = 5

# ── cognitive.inter_command_consistency (Step 8) ────────────────────────────
# CV (stdev / mean) of inter-command IATs. Empirical (this corpus):
# human session CV=0.94 → variable; LLM-simulated CV=0.24 → metronomic;
# anything beyond 1.5 is heuristically "bimodal" (real bimodal detection
# via Hartigan dip is filed for v0.2).
PAUSE_CV_METRONOMIC_MAX: float = 0.40
PAUSE_CV_BIMODAL_MIN: float = 1.50

# ── motor.keystroke_cadence (Step B.1) ──────────────────────────────────────
# Typing bursts split at gaps > IKI_THINK_MAX_S so think-pauses between
# commands don't inflate the within-burst CV. Mirrors the prototype's
# _split_into_bursts (BEHAVE/prototype_extractors/shell/extract.py:275-286).
IKI_THINK_MAX_S: float = 1.50
# Sub-human floor for the "machine" classification — only paired with a
# pathologically uniform CV, since real humans never produce sub-5ms IATs
# in a sustained burst.
IKI_MACHINE_MAX_S: float = 0.005
CV_MACHINE_MAX: float = 0.05
CV_STEADY_MAX: float = 0.50
CV_BURSTY_MAX: float = 1.50
# Need this many input events before we'll claim a cadence at all.
MIN_INPUTS_FOR_CADENCE: int = 5
