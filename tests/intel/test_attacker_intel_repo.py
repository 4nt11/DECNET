"""
Round-trip tests for the ``attacker_intel`` table and its repo helpers.

Covers:
* empty-write upsert path (attacker_uuid as canonical key)
* per-provider partial update preserves untouched columns
* JSON-blob deserialization on read
* TTL bookkeeping (cached_at + expires_at) round-trips intact
* ``get_unenriched_attackers`` returns ``{"uuid", "ip"}`` pairs and
  selects fresh + stale rows while skipping cached ones
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "attacker_intel.db"))
    await r.initialize()
    return r


async def _seed_attacker(repo, ip: str) -> str:
    """Seed an attackers row and return its UUID (the FK target)."""
    now = datetime.now(timezone.utc)
    return await repo.upsert_attacker(
        {"ip": ip, "first_seen": now, "last_seen": now, "event_count": 1}
    )


def _intel_payload(
    *, attacker_uuid: str, ip: str, ttl_hours: int = 24, **overrides
) -> dict:
    now = datetime.now(timezone.utc)
    base = {
        "attacker_uuid": attacker_uuid,
        "attacker_ip": ip,
        "cached_at": now,
        "expires_at": now + timedelta(hours=ttl_hours),
    }
    base.update(overrides)
    return base


@pytest.mark.anyio
async def test_empty_upsert_writes_minimal_row(repo):
    a_uuid = await _seed_attacker(repo, "1.2.3.4")
    row_uuid = await repo.upsert_attacker_intel(
        _intel_payload(attacker_uuid=a_uuid, ip="1.2.3.4")
    )
    assert row_uuid

    row = await repo.get_attacker_intel_by_uuid(a_uuid)
    assert row is not None
    assert row["attacker_uuid"] == a_uuid
    assert row["attacker_ip"] == "1.2.3.4"
    assert row["uuid"] == row_uuid
    assert row["schema_version"] == 1
    # All per-provider verdicts default to None.
    assert row["greynoise_classification"] is None
    assert row["abuseipdb_score"] is None
    assert row["feodo_listed"] is None
    assert row["threatfox_listed"] is None
    assert row["aggregate_verdict"] is None


@pytest.mark.anyio
async def test_partial_provider_update_preserves_others(repo):
    a_uuid = await _seed_attacker(repo, "9.9.9.9")
    # First pass: GreyNoise responds, others lag.
    first_uuid = await repo.upsert_attacker_intel(
        _intel_payload(
            attacker_uuid=a_uuid, ip="9.9.9.9",
            greynoise_classification="malicious",
            greynoise_raw='{"classification":"malicious"}',
            greynoise_queried_at=datetime.now(timezone.utc),
        )
    )
    # Second pass: AbuseIPDB lands. Re-upsert MUST NOT clobber GreyNoise
    # columns — the worker passes only the new fields.
    second_uuid = await repo.upsert_attacker_intel(
        _intel_payload(
            attacker_uuid=a_uuid, ip="9.9.9.9",
            abuseipdb_score=85,
            abuseipdb_raw='{"abuseConfidenceScore":85}',
            abuseipdb_queried_at=datetime.now(timezone.utc),
        )
    )
    assert first_uuid == second_uuid  # same row keyed on attacker_uuid

    row = await repo.get_attacker_intel_by_uuid(a_uuid)
    assert row["greynoise_classification"] == "malicious"
    assert row["greynoise_raw"] == {"classification": "malicious"}
    assert row["abuseipdb_score"] == 85
    assert row["abuseipdb_raw"] == {"abuseConfidenceScore": 85}


@pytest.mark.anyio
async def test_get_missing_returns_none(repo):
    assert await repo.get_attacker_intel_by_uuid("nonexistent-uuid") is None


@pytest.mark.anyio
async def test_unenriched_returns_uuid_ip_pairs(repo):
    fresh_uuid = await _seed_attacker(repo, "10.0.0.1")
    stale_uuid = await _seed_attacker(repo, "10.0.0.2")
    new_uuid = await _seed_attacker(repo, "10.0.0.3")

    # 10.0.0.1 has fresh intel (not due for refresh).
    await repo.upsert_attacker_intel(
        _intel_payload(attacker_uuid=fresh_uuid, ip="10.0.0.1", ttl_hours=24)
    )
    # 10.0.0.2 has stale intel (already expired).
    await repo.upsert_attacker_intel(
        _intel_payload(attacker_uuid=stale_uuid, ip="10.0.0.2", ttl_hours=-1)
    )
    # 10.0.0.3 has no intel row at all.

    pending = await repo.get_unenriched_attackers(limit=10)
    by_uuid = {entry["uuid"]: entry["ip"] for entry in pending}

    assert fresh_uuid not in by_uuid               # fresh, skipped
    assert by_uuid.get(stale_uuid) == "10.0.0.2"   # stale, queue it
    assert by_uuid.get(new_uuid) == "10.0.0.3"     # never enriched
