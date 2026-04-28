"""
Micro-benchmarks for the repository hot paths.

Run with:
    pytest -m bench tests/perf/

These do NOT run in the default suite (see `addopts` in pyproject.toml).
"""
import pytest


pytestmark = pytest.mark.bench


def test_add_log_bench(benchmark, repo, event_loop):
    payload = {
        "decky": "decky-bench",
        "service": "ssh",
        "event_type": "connect",
        "attacker_ip": "10.0.0.1",
        "raw_line": "bench event",
        "fields": "{}",
        "msg": "",
    }

    def run():
        event_loop.run_until_complete(repo.add_log(payload))

    benchmark(run)


def test_get_logs_bench(benchmark, seeded_repo, event_loop):
    def run():
        return event_loop.run_until_complete(seeded_repo.get_logs(limit=50, offset=0))

    result = benchmark(run)
    assert len(result) == 50


def test_get_total_logs_bench(benchmark, seeded_repo, event_loop):
    def run():
        return event_loop.run_until_complete(seeded_repo.get_total_logs())

    benchmark(run)


def test_get_logs_search_bench(benchmark, seeded_repo, event_loop):
    def run():
        return event_loop.run_until_complete(
            seeded_repo.get_logs(limit=50, offset=0, search="service:ssh")
        )

    benchmark(run)


def test_get_user_by_username_bench(benchmark, seeded_repo, event_loop):
    def run():
        return event_loop.run_until_complete(seeded_repo.get_user_by_username("admin"))

    benchmark(run)
