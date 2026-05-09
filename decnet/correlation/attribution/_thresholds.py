"""Calibration thresholds for the attribution engine — every magic
number lives here, named, with the calibration source cited.

v0 values are heuristic. Real calibration ships when red-team
exercises produce labelled trace data
(``ATTRIBUTION-ENGINE.md`` §"Out of scope"). Until then these constants
are the engine's only knobs; aggregate.py never embeds a literal.
"""
from __future__ import annotations

# ── Categorical merger ────────────────────────────────────────────────
# Last-N window size for the categorical state machine. 5 calibrates
# against typical session counts (most attackers are observed < 10
# times before they go quiet — ATTRIBUTION-ENGINE.md §"Open question
# 2"). Operators with long-running attackers will want a wider window
# in v1.
CATEGORICAL_WINDOW_N = 5

# Minimum observations before the merger emits anything other than
# ``unknown``. Below this floor the state machine has no signal.
MIN_OBSERVATIONS_FOR_STATE = 3

# Categorical merger is one-outlier-tolerant: in a window of N=5, the
# state is ``stable`` if at least ``MAJORITY_THRESHOLD`` agree.
CATEGORICAL_MAJORITY_THRESHOLD = 4

# ── Numeric merger ────────────────────────────────────────────────────
# EWMA smoothing factor for numeric primitives. 0.3 weights recent
# observations enough to surface drift quickly without flapping on
# single outliers.
NUMERIC_EWMA_ALPHA = 0.3

# Coefficient-of-variation thresholds: dispersion / |mean|.
NUMERIC_STABLE_DISPERSION_PCT = 0.20    # < 20% of mean → stable
NUMERIC_DRIFT_MEAN_SHIFT_PCT = 0.30     # mean moved > 30% → drifting
NUMERIC_CONFLICT_DISPERSION_PCT = 1.0   # > 100% of mean → conflicted

# ── Hash merger ───────────────────────────────────────────────────────
# Rotations within HASH_DRIFT_WINDOW count toward state transitions.
# Below DRIFT_MAX → drifting; above → conflicted. The values mirror the
# DEBT-032 fingerprint-rotation calibration — bumped by one because
# the attribution engine takes one rotation as evidence-of-life, not
# yet evidence-of-drift.
HASH_DRIFT_MAX = 2
HASH_DRIFT_WINDOW_SECS = 24 * 60 * 60  # 24h

# ── Multi-actor cap ───────────────────────────────────────────────────
# multi_actor confidence is capped to keep the dashboard honest about
# how noisy this signal is. ATTRIBUTION-ENGINE.md §"Open question 1":
# flapping primitives on flaky networks look like two operators.
MULTI_ACTOR_MAX_CONFIDENCE = 0.6

# ── Cross-primitive correlator (Phase 5) ──────────────────────────────
# Minimum number of primitives that must independently flag
# ``multi_actor`` for the same identity before
# ``attribution.profile.multi_actor_suspected`` fires.
MULTI_ACTOR_MIN_PRIMITIVES = 2

# Tick interval for the periodic walk in
# :mod:`decnet.correlation.attribution_worker`. Configurable via env
# var in v1; hardcoded in v0.
MULTI_ACTOR_TICK_SECS = 60.0
