"""CredentialReuse repo tests — upsert idempotency, list pagination, FK backfill."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "reuse.db"))
    await r.initialize()
    return r


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


async def _seed_credential(repo, **overrides):
    base = {
        "attacker_ip": "10.0.0.5",
        "decky_name": "decky-01",
        "service": "ssh",
        "principal": "root",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    base.update(overrides)
    return await repo.upsert_credential(base)


@pytest.mark.anyio
async def test_upsert_inserts_first_observation(repo) -> None:
    sha = _sha256("hunter2")
    out = await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="10.0.0.5",
        decky="decky-01", service="ssh", attempt_count=1,
    )
    assert out is not None
    assert out["inserted"] is True
    assert out["target_count"] == 1
    assert out["confidence"] == 1.0


@pytest.mark.anyio
async def test_upsert_grows_target_count_across_services(repo) -> None:
    """Same secret on two distinct (decky, service) pairs → target_count=2.

    target_count is recomputed from the credentials table, so the test
    must seed actual Credential rows first.
    """
    sha = _sha256("p4ssw0rd")
    await _seed_credential(repo, secret_sha256=sha, decky_name="d1", service="ssh")
    await _seed_credential(repo, secret_sha256=sha, decky_name="d2", service="ftp")

    await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="10.0.0.5",
        decky="d1", service="ssh", attempt_count=1,
    )
    out = await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="10.0.0.5",
        decky="d2", service="ftp", attempt_count=1,
    )
    assert out["inserted"] is False
    assert out["changed"] is True
    assert out["target_count"] == 2


@pytest.mark.anyio
async def test_upsert_dedups_same_decky_service(repo) -> None:
    """Repeated upserts for the same (decky, service) don't grow target_count."""
    sha = _sha256("samepw")
    await _seed_credential(repo, secret_sha256=sha)
    for _ in range(3):
        await repo.upsert_credential_reuse(
            secret_sha256=sha, secret_kind="plaintext", principal="root",
            attacker_uuid=None, attacker_ip="10.0.0.5",
            decky="decky-01", service="ssh", attempt_count=1,
        )
    rows = (await repo.list_credential_reuses(min_target_count=1))[1]
    assert len(rows) == 1
    assert rows[0]["target_count"] == 1
    assert rows[0]["attempt_count"] == 3


@pytest.mark.anyio
async def test_upsert_merges_attacker_lists(repo) -> None:
    """Distinct attacker_uuid/ip values accumulate into the JSON lists."""
    sha = _sha256("shared")
    await _seed_credential(repo, secret_sha256=sha, attacker_ip="1.1.1.1")
    await _seed_credential(
        repo, secret_sha256=sha, attacker_ip="2.2.2.2", decky_name="d2",
    )
    await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid="uuid-A", attacker_ip="1.1.1.1",
        decky="decky-01", service="ssh", attempt_count=1,
    )
    await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid="uuid-B", attacker_ip="2.2.2.2",
        decky="d2", service="ssh", attempt_count=1,
    )
    rows = (await repo.list_credential_reuses(min_target_count=1))[1]
    assert set(rows[0]["attacker_uuids"]) == {"uuid-A", "uuid-B"}
    assert set(rows[0]["attacker_ips"]) == {"1.1.1.1", "2.2.2.2"}


@pytest.mark.anyio
async def test_null_principal_uniqueness(repo) -> None:
    """Two upserts with principal=None go to the same row, not two rows."""
    sha = _sha256("redis-auth")
    await _seed_credential(repo, secret_sha256=sha, service="redis", principal=None)
    for _ in range(2):
        await repo.upsert_credential_reuse(
            secret_sha256=sha, secret_kind="plaintext", principal=None,
            attacker_uuid=None, attacker_ip="1.1.1.1",
            decky="decky-01", service="redis", attempt_count=1,
        )
    rows = (await repo.list_credential_reuses(min_target_count=1))[1]
    assert len(rows) == 1
    assert rows[0]["principal"] is None


@pytest.mark.anyio
async def test_list_filters_by_min_target_count(repo) -> None:
    """min_target_count=2 hides 1-target findings."""
    sha = _sha256("only-once")
    await _seed_credential(repo, secret_sha256=sha)
    await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="1.1.1.1",
        decky="decky-01", service="ssh", attempt_count=1,
    )
    total, rows = await repo.list_credential_reuses(min_target_count=2)
    assert total == 0
    assert rows == []
    total, _ = await repo.list_credential_reuses(min_target_count=1)
    assert total == 1


@pytest.mark.anyio
async def test_list_pagination_orders_by_target_count_desc(repo) -> None:
    sha_a = _sha256("a")
    sha_b = _sha256("b")
    # secret a → 1 target
    await _seed_credential(repo, secret_sha256=sha_a)
    await repo.upsert_credential_reuse(
        secret_sha256=sha_a, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="1.1.1.1",
        decky="d1", service="ssh", attempt_count=1,
    )
    # secret b → 2 targets
    await _seed_credential(repo, secret_sha256=sha_b, service="ssh")
    await _seed_credential(repo, secret_sha256=sha_b, service="ftp", decky_name="d2")
    await repo.upsert_credential_reuse(
        secret_sha256=sha_b, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="1.1.1.1",
        decky="decky-01", service="ssh", attempt_count=1,
    )
    await repo.upsert_credential_reuse(
        secret_sha256=sha_b, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="1.1.1.1",
        decky="d2", service="ftp", attempt_count=1,
    )
    total, rows = await repo.list_credential_reuses(min_target_count=1)
    assert total == 2
    assert rows[0]["secret_sha256"] == sha_b  # higher target_count first


@pytest.mark.anyio
async def test_get_by_id_roundtrip(repo) -> None:
    sha = _sha256("rt")
    await _seed_credential(repo, secret_sha256=sha)
    out = await repo.upsert_credential_reuse(
        secret_sha256=sha, secret_kind="plaintext", principal="root",
        attacker_uuid=None, attacker_ip="1.1.1.1",
        decky="decky-01", service="ssh", attempt_count=1,
    )
    fetched = await repo.get_credential_reuse_by_id(out["id"])
    assert fetched is not None
    assert fetched["id"] == out["id"]
    assert fetched["secret_sha256"] == sha
    assert isinstance(fetched["deckies"], list)


@pytest.mark.anyio
async def test_get_by_id_missing_returns_none(repo) -> None:
    assert await repo.get_credential_reuse_by_id("nope") is None


@pytest.mark.anyio
async def test_update_credential_attacker_uuid_backfills_only_nulls(repo) -> None:
    """The profiler hook must backfill attacker_uuid only on rows where it
    is currently null — pre-existing UUIDs must not be overwritten."""
    sha = _sha256("backfill")
    await _seed_credential(repo, secret_sha256=sha, attacker_ip="9.9.9.9")
    await _seed_credential(
        repo, secret_sha256=sha, attacker_ip="9.9.9.9",
        service="ftp", decky_name="d2",
    )
    # Backfill: both null, both should update.
    n = await repo.update_credential_attacker_uuid("9.9.9.9", "uuid-9")
    assert n == 2

    # Second call: both already set, nothing should change.
    n2 = await repo.update_credential_attacker_uuid("9.9.9.9", "uuid-other")
    assert n2 == 0

    rows = await repo.get_credentials_for_attacker("9.9.9.9")
    assert all(r["attacker_uuid"] == "uuid-9" for r in rows)


@pytest.mark.anyio
async def test_update_credential_attacker_uuid_no_match(repo) -> None:
    n = await repo.update_credential_attacker_uuid("0.0.0.0", "uuid-x")
    assert n == 0
