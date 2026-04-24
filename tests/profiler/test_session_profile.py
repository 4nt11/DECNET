"""
Tests for the session_profile table + repo helpers (SIGNAL_CAPTURE_AUDIT gap #2).

Pre-v1 the ingestion job that populates keystroke-dynamics features is
deferred; this suite exercises the empty-write path (one row per session,
all feature columns NULL) and round-trips a filled row so future work can
land without re-discovering the schema.
"""
import pytest
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "session_profile.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_empty_write_path_ships_null_features(repo):
    # Session close writes `{}` — schema_version defaults to 1, all feature
    # columns stay NULL.
    await repo.upsert_session_profile("sid-1", {})
    row = await repo.get_session_profile("sid-1")
    assert row is not None
    assert row["sid"] == "sid-1"
    assert row["schema_version"] == 1
    assert row["kd_iki_mean"] is None
    assert row["kd_digraph_simhash"] is None
    assert row["total_keystrokes"] is None


@pytest.mark.anyio
async def test_upsert_replaces_existing(repo):
    await repo.upsert_session_profile("sid-2", {})
    await repo.upsert_session_profile(
        "sid-2",
        {
            "kd_iki_mean": 0.120,
            "kd_iki_p95": 0.450,
            "total_keystrokes": 512,
            "session_duration_s": 61.3,
        },
    )
    row = await repo.get_session_profile("sid-2")
    assert row["kd_iki_mean"] == pytest.approx(0.120)
    assert row["kd_iki_p95"] == pytest.approx(0.450)
    assert row["total_keystrokes"] == 512
    assert row["session_duration_s"] == pytest.approx(61.3)


@pytest.mark.anyio
async def test_get_missing_returns_none(repo):
    assert await repo.get_session_profile("does-not-exist") is None
