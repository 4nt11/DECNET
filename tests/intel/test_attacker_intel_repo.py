"""
Round-trip tests for the ``attacker_intel`` table and its repo helpers.

Covers:
* empty-write upsert path
* per-provider partial update
* JSON-blob deserialization on read
* TTL bookkeeping (cached_at + expires_at) round-trips intact
* ``get_unenriched_attacker_ips`` selects fresh + stale, skips cached
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


def _intel_payload(ip: str, *, ttl_hours: int = 24, **overrides) -> dict:
    now = datetime.now(timezone.utc)
    base = {
        "attacker_ip": ip,
        "cached_at": now,
        "expires_at": now + timedelta(hours=ttl_hours),
    }
    base.update(overrides)
    return base


@pytest.mark.anyio
async def test_empty_upsert_writes_minimal_row(repo):
    row_uuid = await repo.upsert_attacker_intel(_intel_payload("1.2.3.4"))
    assert row_uuid

    row = await repo.get_attacker_intel_by_ip("1.2.3.4")
    assert row is not None
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
    # First pass: GreyNoise responds, others lag.
    first_uuid = await repo.upsert_attacker_intel(
        _intel_payload(
            "9.9.9.9",
            greynoise_classification="malicious",
            greynoise_raw='{"classification":"malicious"}',
            greynoise_queried_at=datetime.now(timezone.utc),
        )
    )
    # Second pass: AbuseIPDB lands. Re-upsert MUST NOT clobber GreyNoise
    # columns — the worker passes only the new fields.
    second_uuid = await repo.upsert_attacker_intel(
        _intel_payload(
            "9.9.9.9",
            abuseipdb_score=85,
            abuseipdb_raw='{"abuseConfidenceScore":85}',
            abuseipdb_queried_at=datetime.now(timezone.utc),
        )
    )
    assert first_uuid == second_uuid  # same row

    row = await repo.get_attacker_intel_by_ip("9.9.9.9")
    assert row["greynoise_classification"] == "malicious"
    assert row["greynoise_raw"] == {"classification": "malicious"}
    assert row["abuseipdb_score"] == 85
    assert row["abuseipdb_raw"] == {"abuseConfidenceScore": 85}


@pytest.mark.anyio
async def test_get_missing_returns_none(repo):
    assert await repo.get_attacker_intel_by_ip("0.0.0.0") is None


@pytest.mark.anyio
async def test_unenriched_selects_fresh_and_stale_ips(repo):
    # Seed three attackers via upsert_attacker.
    now = datetime.now(timezone.utc)
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        await repo.upsert_attacker(
            {
                "ip": ip,
                "first_seen": now,
                "last_seen": now,
                "event_count": 1,
            }
        )
    # 10.0.0.1 has fresh intel (not due for refresh).
    await repo.upsert_attacker_intel(_intel_payload("10.0.0.1", ttl_hours=24))
    # 10.0.0.2 has stale intel (already expired).
    await repo.upsert_attacker_intel(_intel_payload("10.0.0.2", ttl_hours=-1))
    # 10.0.0.3 has no intel row at all.

    pending = await repo.get_unenriched_attacker_ips(limit=10)
    assert "10.0.0.1" not in pending  # fresh, skipped
    assert "10.0.0.2" in pending      # stale, queue it
    assert "10.0.0.3" in pending      # never enriched
