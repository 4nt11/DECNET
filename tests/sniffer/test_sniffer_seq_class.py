"""
Unit tests for decnet.sniffer.seq_class.classify_sequence.

Verifies the four classification branches plus the "unknown" fallback
when fewer than the minimum number of samples is supplied.
"""

from __future__ import annotations

from decnet.sniffer.seq_class import classify_sequence


class TestUnknown:
    def test_empty(self):
        assert classify_sequence([]) == "unknown"

    def test_below_min_samples(self):
        # _MIN_SAMPLES is 4 — three samples should not commit.
        assert classify_sequence([10, 20, 30]) == "unknown"


class TestZero:
    def test_all_zero(self):
        assert classify_sequence([0, 0, 0, 0, 0]) == "zero"

    def test_zero_long(self):
        assert classify_sequence([0] * 8) == "zero"


class TestConstant:
    def test_all_same_nonzero(self):
        assert classify_sequence([42, 42, 42, 42]) == "constant"

    def test_mixed_breaks_constant(self):
        assert classify_sequence([42, 42, 43, 42]) != "constant"


class TestIncremental:
    def test_strict_increment_one(self):
        assert classify_sequence([100, 101, 102, 103, 104]) == "incremental"

    def test_increment_with_small_jumps(self):
        # Some kernels skip a few IDs but stay monotonic.
        assert classify_sequence([1000, 1003, 1010, 1012, 1015]) == "incremental"

    def test_decreasing_is_not_incremental(self):
        # Reverse-monotonic could happen on wrap; we treat it as random
        # (callers care about a counter-like signal, not "any monotonic").
        assert classify_sequence([500, 400, 300, 200]) != "incremental"

    def test_huge_jump_breaks_incremental(self):
        # 0x1000 = 4096 is the cutoff; 0x2000 between samples is "random".
        result = classify_sequence([0, 0x2000, 0x4000, 0x6000])
        assert result == "random"


class TestRandom:
    def test_high_variance(self):
        samples = [12345, 0xABCD, 0x1234, 0xFFFF, 0x00FF, 0x7F7F]
        assert classify_sequence(samples) == "random"

    def test_repeated_value_with_one_outlier(self):
        # Not constant (one outlier), not monotonic, not high-variance —
        # still classified as random per the fallthrough rule.
        result = classify_sequence([42, 42, 42, 99])
        assert result == "random"
