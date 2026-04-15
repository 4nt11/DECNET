"""
Live integration tests for the MySQL dashboard backend.

Requires a real MySQL server.  Skipped unless ``DECNET_DB_URL`` (or
``DECNET_MYSQL_TEST_URL``) is exported pointing at a running instance,
e.g. a throw-away docker container:

    docker run -d --rm --name decnet-mysql-test \
        -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=decnet \
        -e MYSQL_USER=decnet -e MYSQL_PASSWORD=decnet \
        -p 3307:3306 mysql:8

    # Either url works; the connecting account MUST have CREATE/DROP DATABASE
    # privilege because each xdist worker uses its own throwaway schema.
    export DECNET_DB_URL='mysql+aiomysql://root:root@127.0.0.1:3307/decnet'
    pytest -m live tests/live/test_mysql_backend_live.py

Each worker creates ``test_decnet_<worker>`` on session start and drops it
on session end.  ``<worker>`` is ``master`` outside xdist, ``gw0``/``gw1``/…
under it, so parallel runs never clash.
"""
from __future__ import annotations

import json
import os
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from decnet.web.db.mysql.repository import MySQLRepository


LIVE_URL = os.environ.get("DECNET_MYSQL_TEST_URL") or os.environ.get("DECNET_DB_URL")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (LIVE_URL and LIVE_URL.startswith("mysql")),
        reason="Set DECNET_DB_URL=mysql+aiomysql://... to run MySQL live tests",
    ),
]


def _worker_id() -> str:
    """Return a stable identifier for the current xdist worker (``master`` when single-process)."""
    return os.environ.get("PYTEST_XDIST_WORKER", "master")


def _split_url(url: str) -> tuple[str, str]:
    """Return (server_url_without_db, test_db_name)."""
    parsed = urlparse(url)
    server_url = urlunparse(parsed._replace(path=""))
    db_name = f"test_decnet_{_worker_id()}"
    return server_url, db_name


def _url_with_db(server_url: str, db_name: str) -> str:
    parsed = urlparse(server_url)
    return urlunparse(parsed._replace(path=f"/{db_name}"))


@pytest.fixture(scope="session")
async def mysql_test_db_url():
    """Create a per-worker throwaway database, yield its URL, drop it on teardown.

    Uses the configured URL's credentials to CREATE/DROP.  If the account
    lacks that privilege you'll see a clear SQL error — grant it with::

        GRANT ALL PRIVILEGES ON `test\\_decnet\\_%`.* TO 'decnet'@'%';

    or point ``DECNET_MYSQL_TEST_URL`` at a root-level URL.
    """
    server_url, db_name = _split_url(LIVE_URL)

    admin = create_async_engine(server_url, isolation_level="AUTOCOMMIT")
    try:
        async with admin.connect() as conn:
            await conn.execute(text(f"DROP DATABASE IF EXISTS `{db_name}`"))
            await conn.execute(text(f"CREATE DATABASE `{db_name}`"))
    finally:
        await admin.dispose()

    yield _url_with_db(server_url, db_name)

    # Teardown — always drop, even if tests errored.
    admin = create_async_engine(server_url, isolation_level="AUTOCOMMIT")
    try:
        async with admin.connect() as conn:
            await conn.execute(text(f"DROP DATABASE IF EXISTS `{db_name}`"))
    finally:
        await admin.dispose()


@pytest.fixture
async def mysql_repo(mysql_test_db_url):
    """Fresh schema per test — truncate between tests to keep them isolated."""
    repo = MySQLRepository(url=mysql_test_db_url)
    await repo.initialize()
    yield repo

    # Per-test cleanup: truncate with FK checks disabled so order doesn't matter.
    async with repo.engine.begin() as conn:
        await conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        for tbl in ("attacker_behavior", "attackers", "logs", "bounty", "state", "users"):
            await conn.execute(text(f"TRUNCATE TABLE `{tbl}`"))
        await conn.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
    await repo.engine.dispose()


async def test_schema_creation_and_admin_seed(mysql_repo):
    user = await mysql_repo.get_user_by_username(os.environ.get("DECNET_ADMIN_USER", "admin"))
    assert user is not None
    assert user["role"] == "admin"


async def test_add_and_query_logs(mysql_repo):
    await mysql_repo.add_log({
        "decky": "decky-01", "service": "ssh", "event_type": "connect",
        "attacker_ip": "10.0.0.7", "raw_line": "connect from 10.0.0.7",
        "fields": json.dumps({"port": 22}), "msg": "conn",
    })
    logs = await mysql_repo.get_logs(limit=10)
    assert any(lg["attacker_ip"] == "10.0.0.7" for lg in logs)
    assert await mysql_repo.get_total_logs() >= 1


async def test_json_field_search(mysql_repo):
    await mysql_repo.add_log({
        "decky": "d1", "service": "ssh", "event_type": "connect",
        "attacker_ip": "1.2.3.4", "raw_line": "x",
        "fields": json.dumps({"username": "root"}), "msg": "",
    })
    hits = await mysql_repo.get_logs(search="username:root")
    assert any("1.2.3.4" == h["attacker_ip"] for h in hits)


async def test_histogram_buckets(mysql_repo):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for i in range(3):
        await mysql_repo.add_log({
            "decky": "h", "service": "ssh", "event_type": "connect",
            "attacker_ip": "9.9.9.9",
            "raw_line": f"line {i}", "fields": "{}", "msg": "",
            "timestamp": (now - timedelta(minutes=i)).isoformat(),
        })
    buckets = await mysql_repo.get_log_histogram(interval_minutes=5)
    assert buckets, "expected at least one histogram bucket"
    for b in buckets:
        assert "time" in b and "count" in b
        assert b["count"] >= 1


async def test_bounty_roundtrip(mysql_repo):
    await mysql_repo.add_bounty({
        "decky": "decky-01", "service": "ssh", "attacker_ip": "10.0.0.1",
        "bounty_type": "credentials",
        "payload": {"username": "root", "password": "toor"},
    })
    out = await mysql_repo.get_bounties()
    assert any(b["bounty_type"] == "credentials" for b in out)


async def test_user_crud(mysql_repo):
    uid = str(_uuid.uuid4())
    await mysql_repo.create_user({
        "uuid": uid, "username": "live_tester",
        "password_hash": "hashed", "role": "viewer", "must_change_password": True,
    })
    u = await mysql_repo.get_user_by_uuid(uid)
    assert u and u["username"] == "live_tester"
    await mysql_repo.update_user_role(uid, "admin")
    u2 = await mysql_repo.get_user_by_uuid(uid)
    assert u2["role"] == "admin"
    ok = await mysql_repo.delete_user(uid)
    assert ok
    assert await mysql_repo.get_user_by_uuid(uid) is None


async def test_purge_clears_tables(mysql_repo):
    await mysql_repo.add_log({
        "decky": "p", "service": "ssh", "event_type": "connect",
        "attacker_ip": "1.1.1.1", "raw_line": "x", "fields": "{}", "msg": "",
    })
    await mysql_repo.purge_logs_and_bounties()
    assert await mysql_repo.get_total_logs() == 0


async def test_large_commands_blob_round_trips(mysql_repo):
    """Attacker.commands must handle >64 KiB (MEDIUMTEXT) — was 1406 errors on TEXT."""
    big_commands = [
        {"service": "ssh", "decky": "d", "command": "A" * 512,
         "timestamp": "2026-04-15T12:00:00+00:00"}
        for _ in range(500)  # ~250 KiB
    ]
    ip = "8.8.8.8"
    now = datetime.now(timezone.utc)
    row_uuid = await mysql_repo.upsert_attacker({
        "ip": ip, "first_seen": now, "last_seen": now,
        "event_count": 0, "service_count": 0, "decky_count": 0,
        "commands": json.dumps(big_commands),
    })
    got = await mysql_repo.get_attacker_by_uuid(row_uuid)
    assert got is not None
    assert len(got["commands"]) == 500
