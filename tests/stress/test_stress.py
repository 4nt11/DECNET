"""
Locust-based stress tests for the DECNET API.

Run:  pytest -m stress tests/stress/ -v -x -n0
Tune: STRESS_USERS=2000 STRESS_SPAWN_RATE=200 STRESS_DURATION=120 pytest -m stress ...
"""

import os

import pytest

from tests.stress.conftest import run_locust, STRESS_USERS, STRESS_SPAWN_RATE, STRESS_DURATION


# Assertion thresholds (overridable via env)
MIN_RPS = int(os.environ.get("STRESS_MIN_RPS", "500"))
MAX_P99_MS = int(os.environ.get("STRESS_MAX_P99_MS", "200"))
MAX_FAIL_RATE = float(os.environ.get("STRESS_MAX_FAIL_RATE", "0.01"))  # 1%


def _print_stats(env, label=""):
    """Print a compact stats summary table."""
    total = env.stats.total
    num_reqs = total.num_requests
    num_fails = total.num_failures
    fail_pct = (num_fails / num_reqs * 100) if num_reqs else 0
    rps = total.total_rps

    print(f"\n{'=' * 70}")
    if label:
        print(f"  {label}")
        print(f"{'=' * 70}")
    print(f"  {'Metric':<30} {'Value':>15}")
    print(f"  {'-' * 45}")
    print(f"  {'Total requests':<30} {num_reqs:>15,}")
    print(f"  {'Failures':<30} {num_fails:>15,} ({fail_pct:.2f}%)")
    print(f"  {'RPS (total)':<30} {rps:>15.1f}")
    print(f"  {'Avg latency (ms)':<30} {total.avg_response_time:>15.1f}")
    print(f"  {'p50 (ms)':<30} {total.get_response_time_percentile(0.50) or 0:>15.0f}")
    print(f"  {'p95 (ms)':<30} {total.get_response_time_percentile(0.95) or 0:>15.0f}")
    print(f"  {'p99 (ms)':<30} {total.get_response_time_percentile(0.99) or 0:>15.0f}")
    print(f"  {'Min (ms)':<30} {total.min_response_time:>15.0f}")
    print(f"  {'Max (ms)':<30} {total.max_response_time:>15.0f}")
    print(f"{'=' * 70}")

    # Per-endpoint breakdown
    print(f"\n  {'Endpoint':<45} {'Reqs':>8} {'Fails':>8} {'Avg(ms)':>10} {'p99(ms)':>10}")
    print(f"  {'-' * 81}")
    for entry in sorted(env.stats.entries.values(), key=lambda e: e.num_requests, reverse=True):
        p99 = entry.get_response_time_percentile(0.99) or 0
        print(
            f"  {entry.method + ' ' + entry.name:<45} "
            f"{entry.num_requests:>8,} "
            f"{entry.num_failures:>8,} "
            f"{entry.avg_response_time:>10.1f} "
            f"{p99:>10.0f}"
        )
    print()


@pytest.mark.stress
def test_stress_rps_baseline(stress_server):
    """Baseline throughput: ramp to STRESS_USERS users, sustain for STRESS_DURATION seconds.

    Asserts:
    - RPS exceeds MIN_RPS
    - p99 latency < MAX_P99_MS
    - Failure rate < MAX_FAIL_RATE
    """
    env = run_locust(
        host=stress_server,
        users=STRESS_USERS,
        spawn_rate=STRESS_SPAWN_RATE,
        duration=STRESS_DURATION,
    )
    _print_stats(env, f"BASELINE: {STRESS_USERS} users, {STRESS_DURATION}s")

    total = env.stats.total
    num_reqs = total.num_requests
    assert num_reqs > 0, "No requests were made"

    rps = total.total_rps
    fail_rate = total.num_failures / num_reqs if num_reqs else 1.0
    p99 = total.get_response_time_percentile(0.99) or 0

    assert rps >= MIN_RPS, f"RPS {rps:.1f} below minimum {MIN_RPS}"
    assert p99 <= MAX_P99_MS, f"p99 {p99:.0f}ms exceeds max {MAX_P99_MS}ms"
    assert fail_rate <= MAX_FAIL_RATE, f"Failure rate {fail_rate:.2%} exceeds max {MAX_FAIL_RATE:.2%}"


@pytest.mark.stress
def test_stress_spike(stress_server):
    """Thundering herd: ramp from 0 to 1000 users in 5 seconds.

    Asserts: no 5xx errors (failure rate < 2%).
    """
    spike_users = int(os.environ.get("STRESS_SPIKE_USERS", "1000"))
    spike_spawn = spike_users // 5  # all users in ~5 seconds

    env = run_locust(
        host=stress_server,
        users=spike_users,
        spawn_rate=spike_spawn,
        duration=15,  # 5s ramp + 10s sustained
    )
    _print_stats(env, f"SPIKE: 0 -> {spike_users} users in 5s")

    total = env.stats.total
    num_reqs = total.num_requests
    assert num_reqs > 0, "No requests were made"

    fail_rate = total.num_failures / num_reqs
    assert fail_rate < 0.02, f"Spike failure rate {fail_rate:.2%} — server buckled under thundering herd"


@pytest.mark.stress
def test_stress_sustained(stress_server):
    """Sustained load: 200 users for 30s. Checks latency doesn't degrade >3x.

    Runs two phases:
    1. Warm-up (10s) to get baseline latency
    2. Sustained (30s) to check for degradation
    """
    sustained_users = int(os.environ.get("STRESS_SUSTAINED_USERS", "200"))

    # Phase 1: warm-up baseline
    env_warmup = run_locust(
        host=stress_server,
        users=sustained_users,
        spawn_rate=sustained_users,  # instant ramp
        duration=10,
    )
    baseline_avg = env_warmup.stats.total.avg_response_time
    _print_stats(env_warmup, f"SUSTAINED warm-up: {sustained_users} users, 10s")

    # Phase 2: sustained
    env_sustained = run_locust(
        host=stress_server,
        users=sustained_users,
        spawn_rate=sustained_users,
        duration=30,
    )
    sustained_avg = env_sustained.stats.total.avg_response_time
    _print_stats(env_sustained, f"SUSTAINED main: {sustained_users} users, 30s")

    assert env_sustained.stats.total.num_requests > 0, "No requests during sustained phase"

    if baseline_avg > 0:
        degradation = sustained_avg / baseline_avg
        print(f"\n  Latency degradation factor: {degradation:.2f}x (baseline {baseline_avg:.1f}ms -> sustained {sustained_avg:.1f}ms)")
        assert degradation < 3.0, (
            f"Latency degraded {degradation:.1f}x under sustained load "
            f"(baseline {baseline_avg:.1f}ms -> {sustained_avg:.1f}ms)"
        )
