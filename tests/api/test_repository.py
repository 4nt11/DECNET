"""
Direct async tests for the configured Repository implementation.
These exercise the DB layer without going through the HTTP stack.
"""
import json
import pytest
from hypothesis import given, settings, strategies as st
from decnet.web.db.factory import get_repository
from .conftest import _FUZZ_SETTINGS


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "test.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_add_and_get_log(repo):
    await repo.add_log({
        "decky": "decky-01",
        "service": "ssh",
        "event_type": "connect",
        "attacker_ip": "10.0.0.1",
        "raw_line": "SSH connect from 10.0.0.1",
        "fields": json.dumps({"port": 22}),
        "msg": "new connection",
    })
    logs = await repo.get_logs(limit=10, offset=0)
    assert len(logs) == 1
    assert logs[0]["decky"] == "decky-01"
    assert logs[0]["service"] == "ssh"
    assert logs[0]["attacker_ip"] == "10.0.0.1"


@pytest.mark.anyio
async def test_get_total_logs(repo):
    for i in range(5):
        await repo.add_log({
            "decky": f"decky-0{i}",
            "service": "ssh",
            "event_type": "connect",
            "attacker_ip": f"10.0.0.{i}",
            "raw_line": "test",
            "fields": "{}",
            "msg": "",
        })
    total = await repo.get_total_logs()
    assert total == 5


@pytest.mark.anyio
async def test_search_filter_by_decky(repo):
    await repo.add_log({"decky": "target", "service": "ssh", "event_type": "connect",
                        "attacker_ip": "1.1.1.1", "raw_line": "x", "fields": "{}", "msg": ""})
    await repo.add_log({"decky": "other",  "service": "ftp", "event_type": "login",
                        "attacker_ip": "2.2.2.2", "raw_line": "y", "fields": "{}", "msg": ""})

    logs = await repo.get_logs(search="decky:target")
    assert len(logs) == 1
    assert logs[0]["decky"] == "target"


@pytest.mark.anyio
async def test_search_filter_by_service(repo):
    await repo.add_log({"decky": "d1", "service": "rdp",  "event_type": "connect",
                        "attacker_ip": "1.1.1.1", "raw_line": "x", "fields": "{}", "msg": ""})
    await repo.add_log({"decky": "d2", "service": "smtp", "event_type": "connect",
                        "attacker_ip": "1.1.1.2", "raw_line": "y", "fields": "{}", "msg": ""})

    logs = await repo.get_logs(search="service:rdp")
    assert len(logs) == 1
    assert logs[0]["service"] == "rdp"


@pytest.mark.anyio
async def test_search_filter_by_json_field(repo):
    await repo.add_log({"decky": "d1", "service": "ssh", "event_type": "connect",
                        "attacker_ip": "1.1.1.1", "raw_line": "x",
                        "fields": json.dumps({"username": "root"}), "msg": ""})
    await repo.add_log({"decky": "d2", "service": "ssh", "event_type": "connect",
                        "attacker_ip": "1.1.1.2", "raw_line": "y",
                        "fields": json.dumps({"username": "admin"}), "msg": ""})

    logs = await repo.get_logs(search="username:root")
    assert len(logs) == 1
    assert json.loads(logs[0]["fields"])["username"] == "root"


@pytest.mark.anyio
async def test_get_logs_after_id(repo):
    for i in range(4):
        await repo.add_log({"decky": "d", "service": "ssh", "event_type": "connect",
                            "attacker_ip": "1.1.1.1", "raw_line": f"line {i}",
                            "fields": "{}", "msg": ""})

    max_id = await repo.get_max_log_id()
    assert max_id == 4

    # Add one more after we captured max_id
    await repo.add_log({"decky": "d", "service": "ssh", "event_type": "connect",
                        "attacker_ip": "1.1.1.1", "raw_line": "line 4", "fields": "{}", "msg": ""})

    new_logs = await repo.get_logs_after_id(last_id=max_id)
    assert len(new_logs) == 1


@pytest.mark.anyio
async def test_full_text_search(repo):
    await repo.add_log({"decky": "d1", "service": "ssh", "event_type": "connect",
                        "attacker_ip": "1.1.1.1", "raw_line": "supersecretstring",
                        "fields": "{}", "msg": ""})
    await repo.add_log({"decky": "d2", "service": "ftp", "event_type": "login",
                        "attacker_ip": "2.2.2.2", "raw_line": "nothing special",
                        "fields": "{}", "msg": ""})

    logs = await repo.get_logs(search="supersecretstring")
    assert len(logs) == 1


@pytest.mark.anyio
async def test_pagination(repo):
    for i in range(10):
        await repo.add_log({"decky": "d", "service": "ssh", "event_type": "connect",
                            "attacker_ip": "1.1.1.1", "raw_line": f"line {i}",
                            "fields": "{}", "msg": ""})

    page1 = await repo.get_logs(limit=4, offset=0)
    page2 = await repo.get_logs(limit=4, offset=4)
    page3 = await repo.get_logs(limit=4, offset=8)

    assert len(page1) == 4
    assert len(page2) == 4
    assert len(page3) == 2
    # No duplicates across pages
    ids1 = {r["id"] for r in page1}
    ids2 = {r["id"] for r in page2}
    assert ids1.isdisjoint(ids2)


@pytest.mark.anyio
async def test_add_and_get_bounty(repo):
    await repo.add_bounty({
        "decky": "decky-01",
        "service": "ssh",
        "attacker_ip": "10.0.0.1",
        "bounty_type": "credentials",
        "payload": {"username": "root", "password": "toor"},
    })
    bounties = await repo.get_bounties(limit=10, offset=0)
    assert len(bounties) == 1
    assert bounties[0]["decky"] == "decky-01"
    assert bounties[0]["bounty_type"] == "credentials"


@pytest.mark.anyio
async def test_user_lifecycle(repo):
    import uuid
    uid = str(uuid.uuid4())
    await repo.create_user({
        "uuid": uid,
        "username": "testuser",
        "password_hash": "hashed_pw",
        "role": "viewer",
        "must_change_password": True,
    })

    user = await repo.get_user_by_username("testuser")
    assert user is not None
    assert user["role"] == "viewer"
    assert user["must_change_password"] == 1

    await repo.update_user_password(uid, "new_hashed_pw", must_change_password=False)
    updated = await repo.get_user_by_uuid(uid)
    assert updated["password_hash"] == "new_hashed_pw"
    assert updated["must_change_password"] == 0


@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    raw_line=st.text(max_size=2048),
    fields=st.text(max_size=2048),
    attacker_ip=st.text(max_size=128),
)
async def test_fuzz_add_log(repo, raw_line: str, fields: str, attacker_ip: str) -> None:
    """Fuzz add_log with arbitrary strings — must never raise uncaught exceptions."""
    try:
        await repo.add_log({
            "decky": "fuzz-decky",
            "service": "ssh",
            "event_type": "connect",
            "attacker_ip": attacker_ip,
            "raw_line": raw_line,
            "fields": fields,
            "msg": "",
        })
    except Exception as exc:
        pytest.fail(f"add_log raised unexpectedly: {exc}")
