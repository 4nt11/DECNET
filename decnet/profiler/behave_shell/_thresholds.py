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

# ── output error-signal helper (Step D.0) ──────────────────────────────────
# The canonical bash/sh error fingerprints live in ``_parse.py`` as
# ``_OUTPUT_ERROR_PATTERNS`` (compiled regexes). They're not threshold
# numbers, so they live next to the helper that uses them rather than
# here. This v0.1 heuristic will be subsumed by Phase F.0's prompt
# parser (PS1 echo + exit-code sniff), at which point this comment and
# the patterns block move to ``_parse.py``'s prompt section. Until then,
# any drift in registry value definitions for ``error_resilience.*`` or
# ``cognitive_load`` must be reflected by editing the patterns tuple
# (not a constant, so no boundary-band logic applies).

# ── cognitive.cognitive_load (Step D.1) ─────────────────────────────────────
# Composite ∈ [0, 1] over three sub-signals (each clipped to [0, 1]):
#
#   A = chunking_load         = median_intra_cmd_cv / CHUNKING_REF_CV
#   B = error_load            = errored_cmds / total_cmds
#   C = pace_variability_load = (stdev / mean of inter_cmd_iats) / PACE_REF_CV
#
# load = mean(A, B, C); bucket:
#   load <  COGNITIVE_LOAD_LOW_MAX     → low
#   load <  COGNITIVE_LOAD_MEDIUM_MAX  → medium
#   else                               → high
#
# v0.1 thresholds — D.8 re-tunes once D.1-D.7 are stable. The reference
# CVs (CHUNKING_REF_CV / PACE_REF_CV) are the value at which that single
# component saturates to a load contribution of 1.0; anything past
# saturates the term but doesn't double-count.
COGNITIVE_LOAD_CHUNKING_REF_CV: float = 1.00
COGNITIVE_LOAD_PACE_REF_CV: float = 1.50
COGNITIVE_LOAD_LOW_MAX: float = 0.33
COGNITIVE_LOAD_MEDIUM_MAX: float = 0.67

# ── cognitive.exploration_style (Step D.2) ─────────────────────────────────
# Two-axis classification over the first_token_hash sequence:
#
#   repetition_rate (R) = 1 - (unique_first_tokens / total_commands)
#   backtrack_rate  (J) = transitions where commands[i+1].first_token_hash
#                         appeared anywhere in commands[0..i-1] but is NOT
#                         equal to commands[i].first_token_hash (jumping
#                         back to an older tool, not just repeating).
#
#   J >= EXPLORATION_CHAOTIC_BACKTRACK_MIN  → chaotic
#   else if R >= EXPLORATION_TARGETED_REP_MIN → targeted
#   else                                    → methodical
#
# Methodical = low repetition, low backtracks (linear progression through
# novel tools). Targeted = high repetition (drilling the same tool).
# Chaotic = jumping between prior tools without a clear thread.
# v0.1; D.8 re-tunes.
EXPLORATION_TARGETED_REP_MIN: float = 0.50
EXPLORATION_CHAOTIC_BACKTRACK_MIN: float = 0.30

# ── cognitive.planning_depth (Step D.3) ────────────────────────────────────
# Distribution of inter-command IATs.
#   deep_pause_fraction      = (count of inter_cmd_iats > IKI_THINK_MAX_S) / N
#   reactive_pause_fraction  = (count of inter_cmd_iats <= INTER_CMD_INSTANT_MAX) / N
#
#   deep_pause_fraction      >= PLANNING_DEEP_MIN     → deep
#   reactive_pause_fraction  >= PLANNING_REACTIVE_MIN → reactive
#   otherwise                                         → shallow
#
# v0.1; D.8 re-tunes once D.1-D.7 are stable.
PLANNING_DEEP_MIN: float = 0.40
PLANNING_REACTIVE_MIN: float = 0.50

# ── cognitive.tool_vocabulary (Step D.4) ───────────────────────────────────
# Absolute count of distinct first_token_hashes across the session.
#
#   distinct <= TOOL_VOCAB_NARROW_MAX  → narrow
#   distinct >= TOOL_VOCAB_BROAD_MIN   → broad
#   otherwise                          → moderate
#
# Absolute, not normalised. A 3-command session with 3 unique tools is
# ``narrow`` not ``broad`` — the operator simply hasn't shown range yet.
# Sample-size honesty drops confidence below MIN_COMMANDS_FOR_FULL_CONFIDENCE.
# v0.1; D.8 re-tunes.
TOOL_VOCAB_NARROW_MAX: int = 3
TOOL_VOCAB_BROAD_MIN: int = 10

# ── cognitive.error_resilience.frustration_typing (Step D.6) ───────────────
# Compare the median within-command IAT of commands *following* an
# errored command against the same statistic for commands following a
# successful command. The relative absolute delta:
#
#   delta = |median_post_error - median_post_success| / median_post_success
#
#   delta < FRUSTRATION_LOW_MAX        → low
#   delta < FRUSTRATION_MODERATE_MAX   → moderate
#   else                               → high
#
# v0.1; D.8 re-tunes.
FRUSTRATION_LOW_MAX: float = 0.10
FRUSTRATION_MODERATE_MAX: float = 0.30

# ── temporal.session_duration (Step E.1) ───────────────────────────────────
# Bucket edges (seconds) for ``ctx.duration_s``:
#
#   duration_s <  SESSION_DURATION_SHORT_MAX     → short
#   duration_s <  SESSION_DURATION_MEDIUM_MAX    → medium
#   duration_s <  SESSION_DURATION_LONG_MAX      → long
#   else                                         → marathon
#
# 60s / 600s / 3600s are the BEHAVE-EXTRACTOR.md defaults; D.8-equivalent
# re-tune for E lands when calibration corpus is run.
SESSION_DURATION_SHORT_MAX: float = 60.0
SESSION_DURATION_MEDIUM_MAX: float = 600.0
SESSION_DURATION_LONG_MAX: float = 3600.0

# ── temporal.escalation_pattern (Step E.2) ─────────────────────────────────
# Bin commands into non-overlapping windows. Width is dynamic:
#
#   width = max(ESCALATION_WINDOW_MIN_S, duration_s / ESCALATION_WINDOW_TARGET)
#
# so a 30s session uses 10s windows (3 windows) and a 1h session uses
# 6min windows (10 windows). CV of per-window counts + zero-window
# fraction classify:
#
#   zero_frac >= ESCALATION_BURSTY_ZERO_FRAC AND CV >= ESCALATION_BURSTY_CV
#       → bursty       (silences then spikes)
#   CV <  ESCALATION_SUSTAINED_CV
#       → sustained    (steady cadence throughout)
#   else
#       → erratic      (variable but no real silence pattern)
#
# v0.1; corpus re-tune deferred. Sample-size honesty caps confidence
# below ESCALATION_MIN_WINDOWS or ESCALATION_MIN_COMMANDS.
ESCALATION_WINDOW_MIN_S: float = 10.0
ESCALATION_WINDOW_TARGET: int = 10
ESCALATION_BURSTY_ZERO_FRAC: float = 0.30
ESCALATION_BURSTY_CV: float = 1.00
ESCALATION_SUSTAINED_CV: float = 0.50
ESCALATION_MIN_WINDOWS: int = 5
ESCALATION_MIN_COMMANDS: int = 5

# ── temporal.lifecycle_markers.landing_ritual (Step E.3) ──────────────────
# How many of the first ``LANDING_RITUAL_FIRST_N`` commands must hit
# the recon-token set (uname / id / whoami / pwd / hostname / w / who)
# for the session to count as having a landing ritual.
LANDING_RITUAL_FIRST_N: int = 5
LANDING_RITUAL_HIT_MIN: int = 2
LANDING_RITUAL_MIN_COMMANDS: int = 3

# ── F.0 prompt-line detector ──────────────────────────────────────────────
# A prompt line in the output stream ends with one of these characters
# followed by a space or EOL. ``$`` and ``#`` are sh/bash; ``%`` is zsh;
# ``>`` is fish / cmd.exe / powershell (disambiguated by line content
# at F.1 time). Capped at 256 chars to bound memory; ANTI authorised
# retaining PS1 text on ctx (PII relaxation), but a malicious operator
# inflating the prompt buffer is still bounded.
PROMPT_SUFFIX_CHARS: frozenset[str] = frozenset({"$", "#", "%", ">"})
PROMPT_LINE_MAX_CHARS: int = 256

# ── environmental.shell_type (Step F.1) ────────────────────────────────────
# Below this many detected prompt-lines, drop confidence (sample-size
# honesty). Above, the shell-type vote is robust.
SHELL_TYPE_MIN_PROMPTS: int = 3

# ── environmental.locale (Step F.3) ────────────────────────────────────────
# Below this many characters in the parsed locale value, treat as
# noise and skip emission (a single 'C' or 'en' is too thin).
LOCALE_MIN_VALUE_LENGTH: int = 2

# ── environmental.keyboard_layout (Step F.4) ───────────────────────────────
# ANTI authorised dropping the PII boundary for this primitive — typed
# bigram/unigram histograms ride on SessionContext to feed two
# independent layout signals:
#
#   1. English-bigram saturation (presumed-QWERTY signal)
#   2. Layout-artefact unigram rates (q for AZERTY, z/y swap for QWERTZ)
#
# Sample-size floor; below this typed-letter-count we skip emission.
LAYOUT_MIN_TYPED_LETTERS: int = 200
# Cap on bigram histogram size — bound memory while keeping the top
# bigrams that drive the saturation signal.
LAYOUT_BIGRAM_TOP_N: int = 64
# Top-10 English bigrams. Their summed frequency floor presumes QWERTY
# (the dominant English-typing layout).
LAYOUT_TOP_ENG_BIGRAMS: frozenset[str] = frozenset({
    "th", "he", "in", "er", "an", "re", "on", "at", "nd", "ha",
})
# Layout-artefact thresholds. Fractions are over total ASCII-letter typed.
LAYOUT_AZERTY_Q_MIN: float = 0.020      # high `q` rate (mistyping AZERTY's `a`)
LAYOUT_AZERTY_ENG_MAX: float = 0.050    # AND low English saturation
LAYOUT_QWERTZ_Z_MIN: float = 0.030      # high `z` rate (German content / QWERTZ)
LAYOUT_QWERTZ_Y_MAX: float = 0.010      # AND `y` swap signature
LAYOUT_QWERTY_ENG_MIN: float = 0.080    # English-bigram saturation floor

# ── environmental.numpad_usage (Step F.5) ──────────────────────────────────
# A digit run = NUMPAD_RUN_MIN consecutive single-char digit events
# whose pairwise IATs are all ≤ NUMPAD_FAST_IAT_S. Numpad muscle memory
# produces faster digit IATs than touch-typing on the top row.
NUMPAD_FAST_IAT_S: float = 0.050
NUMPAD_RUN_MIN: int = 4
# Below this many typed chars total, skip emission (no honest signal).
NUMPAD_MIN_TYPED_CHARS: int = 50

# ── temporal.lifecycle_markers.exit_behavior (Step E.4, unblocked by F.0) ──
# How many of the last commands to inspect for cleanup-family tokens.
EXIT_BEHAVIOR_LOOKBACK_K: int = 3

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

# ── motor.motor_stability (Step B.2) ────────────────────────────────────────
# Tremor proxy: fraction of within-burst IATs below TREMOR_FAST_FLOOR_S
# (30 ms — physiologically implausible double-press floor; humans can't
# reliably produce IATs below ~50 ms in sustained typing). High rate
# of sub-floor IATs flags double-press / motor twitch / stuck-key.
TREMOR_FAST_FLOOR_S: float = 0.030
TREMOR_RATE_MIN: float = 0.10  # ≥10% sub-floor → tremor

# ── motor.error_correction (Step B.3) ───────────────────────────────────────
# Backspace within this many seconds of the preceding key = "caught the
# typo mid-keystroke" (immediate). Beyond this = the operator paused,
# noticed, then went back (deferred).
BACKSPACE_IMMEDIATE_MAX_S: float = 0.50

# ── motor.command_chunking (Step B.4) ───────────────────────────────────────
# Median CV of within-command IATs. Below this → fluent (steady within
# each command); above → fragmented (operator pauses mid-command).
CMD_CHUNKING_FLUENT_CV_MAX: float = 0.50

# ── motor.shell_mastery.* (Phase C) ─────────────────────────────────────────
# Readline control bytes counted toward ``shortcut_usage``. The seven
# pinned by BEHAVE-EXTRACTOR.md §Phase C (line 472):
#   ^A start-of-line  ^E end-of-line  ^W kill-prev-word
#   ^U kill-line      ^R reverse-i-search  ^B back-char  ^F forward-char
# v0.2 may extend to ^K/^Y/^L/^D/^P/^N once corpus calibration justifies it.
# Note: ^U / ^W also feed ``motor.error_correction`` (Step B.3) via the
# ``kill_line_count`` channel — these are independent measurements over
# the same byte stream, not double-counting.
SHORTCUT_CTRL_BYTES: frozenset[str] = frozenset({
    "\x01", "\x05", "\x17", "\x15", "\x12", "\x02", "\x06",
})

# motor.shell_mastery.tab_completion — fraction of commands containing
# at least one ``\t`` keystroke. Registry buckets per BEHAVE-EXTRACTOR.md
# line 471: ``none`` (0%), ``occasional`` (<30%), ``habitual`` (≥50%).
# The 30%-50% gap rounds down to ``occasional`` — the registry's own gap.
TAB_COMPLETION_OCCASIONAL_MAX: float = 0.30
TAB_COMPLETION_HABITUAL_MIN: float = 0.50

# motor.shell_mastery.shortcut_usage — total readline ctrl-byte
# keystrokes per command. Registry buckets are qualitative
# (``none / moderate / heavy``); v0.1 thresholds are best-guesses
# pinned for five-class corpus calibration. Re-tune once HUMAN /
# YOU-sim / LW-sim / CLAUDE-FF / CLAUDE-CL data lands.
#   0/cmd        → none
#   <0.05/cmd    → none (counted shortcuts but rare; rounds down)
#   0.05-0.30    → moderate
#   ≥0.30/cmd    → heavy
SHORTCUT_USAGE_MODERATE_MIN: float = 0.05
SHORTCUT_USAGE_HEAVY_MIN: float = 0.30

# motor.shell_mastery.pipe_chaining_depth — median ``|`` count across
# commands. Pipes are counted on every byte (typed AND pasted) — a
# pasted pipeline still indicates pipeline fluency the operator chose
# to execute. Registry buckets per BEHAVE-EXTRACTOR.md line 473:
#   median ≤ 1  → shallow (no pipeline at all, or one stage)
#   median == 2 → moderate
#   median ≥ 3  → deep
# Median is integer-valued (sum of ints over commands), so the
# boundaries here are integer step boundaries; the proximity-band
# logic uses integer equality.
PIPE_CHAINING_MODERATE_MEDIAN: int = 2
PIPE_CHAINING_DEEP_MEDIAN: int = 3

# Sample-size floor below which Phase C primitives drop confidence to
# 0.40 (sample-size honesty). Mirrors MIN_COMMANDS_FOR_FULL_CONFIDENCE
# but is named separately so a future tune can move them independently.
SHELL_MASTERY_MIN_COMMANDS: int = 5

# Width of the "near a bucket boundary" band (relative to the boundary)
# used by Phase C primitives. ±10% of the boundary value drops
# confidence by 0.20 per BEHAVE-EXTRACTOR.md §"Threshold proximity".
SHELL_MASTERY_BOUNDARY_BAND: float = 0.10
