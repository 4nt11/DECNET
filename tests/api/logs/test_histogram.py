"""
Histogram bucketing tests using freezegun.

freeze_time controls Python's datetime.now() so we can compute
explicit bucket timestamps deterministically, then pass them to
add_log and verify SQLite groups them into the right buckets.
"""
import json
import pytest
from datetime import datetime, timedelta
from freezegun import freeze_time
from hypothesis import given, settings, strategies as st
from decnet.web.db.sqlite.repository import SQLiteRepository
from ..conftest import _FUZZ_SETTINGS


@pytest.fixture
def repo(tmp_path):
    return SQLiteRepository(db_path=str(tmp_path / "histogram_test.db"))


def _log(decky="d", service="ssh", ip="1.2.3.4", timestamp=None):
    return {
        "decky": decky,
        "service": service,
        "event_type": "connect",
        "attacker_ip": ip,
        "raw_line": "test",
        "fields": "{}",
        "msg": "",
        **({"timestamp": timestamp} if timestamp else {}),
    }


@pytest.mark.anyio
async def test_histogram_empty_db(repo):
    result = await repo.get_log_histogram()
    assert result == []


@pytest.mark.anyio
@freeze_time("2026-04-09 12:00:00")
async def test_histogram_single_bucket(repo):
    now = datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")

    for _ in range(5):
        await repo.add_log(_log(timestamp=ts))

    result = await repo.get_log_histogram(interval_minutes=15)
    assert len(result) == 1
    assert result[0]["count"] == 5


@pytest.mark.anyio
@freeze_time("2026-04-09 12:00:00")
async def test_histogram_two_buckets(repo):
    now = datetime.now()
    bucket_a = now.strftime("%Y-%m-%d %H:%M:%S")
    bucket_b = (now + timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S")

    for _ in range(3):
        await repo.add_log(_log(timestamp=bucket_a))
    for _ in range(7):
        await repo.add_log(_log(timestamp=bucket_b))

    result = await repo.get_log_histogram(interval_minutes=15)
    assert len(result) == 2
    counts = {r["count"] for r in result}
    assert counts == {3, 7}


@pytest.mark.anyio
@freeze_time("2026-04-09 12:00:00")
async def test_histogram_respects_start_end_filter(repo):
    now = datetime.now()
    inside  = now.strftime("%Y-%m-%d %H:%M:%S")
    outside = (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")

    await repo.add_log(_log(timestamp=inside))
    await repo.add_log(_log(timestamp=outside))

    start = (now - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    end   = (now + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")

    result = await repo.get_log_histogram(start_time=start, end_time=end, interval_minutes=15)
    total = sum(r["count"] for r in result)
    assert total == 1


@pytest.mark.anyio
@freeze_time("2026-04-09 12:00:00")
async def test_histogram_search_filter(repo):
    now = datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")

    await repo.add_log(_log(decky="ssh-decky", service="ssh", timestamp=ts))
    await repo.add_log(_log(decky="ftp-decky", service="ftp", timestamp=ts))

    result = await repo.get_log_histogram(search="service:ssh", interval_minutes=15)
    total = sum(r["count"] for r in result)
    assert total == 1


@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    search=st.one_of(st.none(), st.text(max_size=512)),
    interval_minutes=st.integers(min_value=1, max_value=10000),
)
async def test_fuzz_histogram(repo, search: str | None, interval_minutes: int) -> None:
    """Fuzz histogram params — must never raise uncaught exceptions."""
    try:
        await repo.get_log_histogram(search=search, interval_minutes=interval_minutes)
    except Exception as exc:
        pytest.fail(f"get_log_histogram raised unexpectedly: {exc}")
