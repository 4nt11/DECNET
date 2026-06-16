# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Sequence-pattern classifier for TCP/IP fields that are useful as a tooling
fingerprint when sampled across multiple packets from the same source.

Two callers today:
- IP-ID sequence per attacker (random/incremental/zero/constant).
- TCP ISN sequence per attacker; modern stacks randomise, so a non-random
  result is itself a strong signal (legacy stacks, custom raw-socket tools).

Pure stdlib so it stays trivially unit-testable.
"""

from __future__ import annotations

import statistics

# Minimum samples needed for a meaningful classification. Below this we
# return "unknown" rather than guess from 1-3 noisy values.
_MIN_SAMPLES = 4

# Max plausible delta for an "incremental" classification. The IP-ID field
# is 16-bit so kernel-emitted increments wrap rapidly under load — anything
# over 4096 between consecutive SYNs from the same host is almost certainly
# random rather than a counter we just happen to be sampling sparsely.
_INCREMENTAL_MAX_DELTA = 0x1000

# Coefficient-of-variation threshold above which we call a sequence random.
# stddev/mean > 0.5 is well past anything a counter would produce.
_RANDOM_CV_THRESHOLD = 0.5


def classify_sequence(samples: list[int]) -> str:
    """
    Classify an integer sequence as one of:
      - "zero":        every sample is 0
      - "constant":    every sample is the same non-zero value
      - "incremental": strictly monotonic with small positive deltas
      - "random":      high coefficient of variation, no monotonic pattern
      - "unknown":     fewer than _MIN_SAMPLES samples

    Order is preserved — pass the deque/list in arrival order.
    """
    if len(samples) < _MIN_SAMPLES:
        return "unknown"

    if all(s == 0 for s in samples):
        return "zero"

    first = samples[0]
    if all(s == first for s in samples):
        return "constant"

    deltas = [b - a for a, b in zip(samples, samples[1:])]
    if all(0 < d <= _INCREMENTAL_MAX_DELTA for d in deltas):
        return "incremental"

    mean = statistics.fmean(samples)
    if mean > 0:
        stdev = statistics.pstdev(samples)
        if stdev / mean > _RANDOM_CV_THRESHOLD:
            return "random"

    return "random"
