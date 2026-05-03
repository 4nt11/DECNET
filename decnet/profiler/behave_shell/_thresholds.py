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
