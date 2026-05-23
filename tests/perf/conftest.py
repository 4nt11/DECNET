# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def repo(tmp_path_factory, event_loop):
    path = tmp_path_factory.mktemp("perf") / "bench.db"
    r = get_repository(db_path=str(path))
    event_loop.run_until_complete(r.initialize())
    return r


@pytest.fixture(scope="session")
def seeded_repo(repo, event_loop):
    async def _seed():
        for i in range(1000):
            await repo.add_log({
                "decky": f"decky-{i % 10:02d}",
                "service": ["ssh", "ftp", "smb", "rdp"][i % 4],
                "event_type": "connect",
                "attacker_ip": f"10.0.{i // 256}.{i % 256}",
                "raw_line": f"event {i}",
                "fields": "{}",
                "msg": "",
            })
    event_loop.run_until_complete(_seed())
    return repo
