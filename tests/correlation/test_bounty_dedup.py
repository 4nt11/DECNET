"""
Tests for bounty deduplication.

Identical (bounty_type, attacker_ip, payload) tuples must be dropped so
aggressive scanners cannot saturate the bounty table.
"""
import pytest
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "test.db"))
    await r.initialize()
    return r


_BASE = {
    "decky": "decky-01",
    "service": "ssh",
    "attacker_ip": "10.0.0.1",
    "bounty_type": "credential",
    "payload": {"username": "admin", "password": "password"},
}


@pytest.mark.anyio
async def test_duplicate_dropped(repo):
    await repo.add_bounty({**_BASE})
    await repo.add_bounty({**_BASE})
    bounties = await repo.get_bounties()
    assert len(bounties) == 1


@pytest.mark.anyio
async def test_different_ip_not_deduped(repo):
    await repo.add_bounty({**_BASE})
    await repo.add_bounty({**_BASE, "attacker_ip": "10.0.0.2"})
    bounties = await repo.get_bounties()
    assert len(bounties) == 2


@pytest.mark.anyio
async def test_different_type_not_deduped(repo):
    await repo.add_bounty({**_BASE})
    await repo.add_bounty({**_BASE, "bounty_type": "fingerprint"})
    bounties = await repo.get_bounties()
    assert len(bounties) == 2


@pytest.mark.anyio
async def test_different_payload_not_deduped(repo):
    await repo.add_bounty({**_BASE})
    await repo.add_bounty({**_BASE, "payload": {"username": "root", "password": "toor"}})
    bounties = await repo.get_bounties()
    assert len(bounties) == 2


@pytest.mark.anyio
async def test_flood_protection(repo):
    for _ in range(50):
        await repo.add_bounty({**_BASE})
    bounties = await repo.get_bounties()
    assert len(bounties) == 1


@pytest.mark.anyio
async def test_dict_payload_dedup(repo):
    """Payload passed as dict (pre-serialisation path) is still deduped."""
    await repo.add_bounty({**_BASE, "payload": {"username": "admin", "password": "password"}})
    await repo.add_bounty({**_BASE, "payload": {"username": "admin", "password": "password"}})
    bounties = await repo.get_bounties()
    assert len(bounties) == 1


@pytest.mark.anyio
async def test_string_payload_dedup(repo):
    """Payload passed as pre-serialised string is also deduped."""
    import json
    p = json.dumps({"username": "admin", "password": "password"})
    await repo.add_bounty({**_BASE, "payload": p})
    await repo.add_bounty({**_BASE, "payload": p})
    bounties = await repo.get_bounties()
    assert len(bounties) == 1
