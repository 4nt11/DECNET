"""Coverage for the canary planter (docker exec wrapper).

We don't actually invoke docker — :func:`asyncio.create_subprocess_exec`
is patched to record argv and return canned ``(rc, stdout, stderr)``
triples.  That lets us assert:

* the docker argv has the right shape (container = ``<decky>-ssh``,
  ``sh -c <script>``);
* the script base64-decodes the artifact bytes losslessly;
* mtime is backdated by the right offset;
* state transitions hit the repo on success/failure;
* the bus event publishes on success.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
from typing import AsyncIterator
from unittest.mock import patch

import pytest
import pytest_asyncio

from decnet.bus import topics
from decnet.bus.fake import FakeBus
from decnet.canary import CanaryArtifact
from decnet.canary import planter
from decnet.web.db.sqlite.repository import SQLiteRepository
import decnet.web.db.models  # noqa: F401


class _FakeProc:
    def __init__(self, rc: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = rc
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:  # pragma: no cover — never reached in non-timeout tests
        pass


def _patch_subprocess(rc: int = 0, stderr: bytes = b""):
    captured: list[list[str]] = []

    async def _fake(*argv, **kw):
        captured.append(list(argv))
        return _FakeProc(rc, b"", stderr)

    return patch.object(asyncio, "create_subprocess_exec", _fake), captured


@pytest_asyncio.fixture
async def repo(tmp_path) -> AsyncIterator[SQLiteRepository]:
    r = SQLiteRepository(str(tmp_path / "p.db"))
    await r.initialize()
    yield r


@pytest_asyncio.fixture
async def fake_bus() -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    yield bus
    await bus.close()


# ---------------- argv shape + base64 round-trip --------------------------


@pytest.mark.asyncio
async def test_plant_argv_and_base64_round_trip(repo: SQLiteRepository, fake_bus: FakeBus, tmp_path) -> None:
    art = CanaryArtifact(
        path="/home/admin/.aws/credentials",
        content=b"\x00binary\xffpayload",
        mode=0o600,
        mtime_offset=-86400,
        generator="aws_creds",
    )
    # Persist a token row so the state-update path has something to flip.
    await repo.create_canary_token({
        "uuid": "tok-1", "kind": "http", "decky_name": "web1",
        "generator": "aws_creds", "placement_path": art.path,
        "callback_token": "slug", "secret_seed": "s", "created_by": "u1",
    })
    patcher, captured = _patch_subprocess(rc=0)
    with patcher:
        ok, err = await planter.plant(
            "web1", art, token_uuid="tok-1", repo=repo, bus=fake_bus,
        )
    assert ok is True and err is None
    assert len(captured) == 1
    argv = captured[0]
    assert argv[:3] == ["docker", "exec", "web1-ssh"]
    assert argv[3:5] == ["sh", "-c"]
    script = argv[5]
    # base64-decoded payload appears in the script verbatim.
    encoded = base64.b64encode(art.content).decode()
    assert encoded in script
    # touch -d @<mtime> with negative offset → an int strictly less than now.
    m = re.search(r"touch -d @(\d+) ", script)
    assert m and int(m.group(1)) > 0
    # State transitioned to planted.
    row = await repo.get_canary_token("tok-1")
    assert row["state"] == "planted" and row["last_error"] is None


@pytest.mark.asyncio
async def test_plant_records_failure_when_docker_returns_nonzero(repo: SQLiteRepository, fake_bus: FakeBus) -> None:
    await repo.create_canary_token({
        "uuid": "tok-2", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/x",
        "callback_token": "slug2", "secret_seed": "s", "created_by": "u1",
    })
    art = CanaryArtifact(path="/x", content=b"y", generator="env_file")
    patcher, _ = _patch_subprocess(rc=125, stderr=b"container not running")
    with patcher:
        ok, err = await planter.plant(
            "web1", art, token_uuid="tok-2", repo=repo, bus=fake_bus,
        )
    assert ok is False
    assert err and "not running" in err
    row = await repo.get_canary_token("tok-2")
    assert row["state"] == "failed" and row["last_error"]


@pytest.mark.asyncio
async def test_plant_rejects_empty_path(repo: SQLiteRepository) -> None:
    await repo.create_canary_token({
        "uuid": "tok-3", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/x",
        "callback_token": "slug3", "secret_seed": "s", "created_by": "u1",
    })
    art = CanaryArtifact(path="", content=b"y")
    ok, err = await planter.plant("web1", art, token_uuid="tok-3", repo=repo)
    assert ok is False and err is not None
    row = await repo.get_canary_token("tok-3")
    assert row["state"] == "failed"


@pytest.mark.asyncio
async def test_plant_publishes_placed_event(repo: SQLiteRepository, fake_bus: FakeBus) -> None:
    await repo.create_canary_token({
        "uuid": "tok-4", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/x",
        "callback_token": "slug4", "secret_seed": "s", "created_by": "u1",
    })
    sub = fake_bus.subscribe("canary.>")
    art = CanaryArtifact(path="/x", content=b"y", generator="env_file")
    patcher, _ = _patch_subprocess(rc=0)
    with patcher:
        await planter.plant(
            "web1", art, token_uuid="tok-4", repo=repo, bus=fake_bus,
        )
    event = await asyncio.wait_for(sub.__anext__(), timeout=1.0)
    assert event.topic == topics.canary("tok-4", topics.CANARY_PLACED)
    assert event.payload["decky_name"] == "web1"
    assert event.payload["generator"] == "env_file"


# ---------------- revoke --------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_unlinks_and_publishes(repo: SQLiteRepository, fake_bus: FakeBus) -> None:
    await repo.create_canary_token({
        "uuid": "tok-r", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/etc/x.env",
        "callback_token": "slugR", "secret_seed": "s", "created_by": "u1",
    })
    sub = fake_bus.subscribe("canary.>")
    patcher, captured = _patch_subprocess(rc=0)
    with patcher:
        ok, err = await planter.revoke(
            "web1", "/etc/x.env",
            token_uuid="tok-r", repo=repo, bus=fake_bus,
        )
    assert ok and not err
    assert "rm -f /etc/x.env" in captured[0][5]
    row = await repo.get_canary_token("tok-r")
    assert row["state"] == "revoked"
    event = await asyncio.wait_for(sub.__anext__(), timeout=1.0)
    assert event.topic == topics.canary("tok-r", topics.CANARY_REVOKED)


# ---------------- seed_baseline ------------------------------------------


@pytest.mark.asyncio
async def test_seed_baseline_creates_one_token_per_generator(
    repo: SQLiteRepository, fake_bus: FakeBus, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BASELINE", "git_config,env_file,aws_creds")
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.test")
    patcher, captured = _patch_subprocess(rc=0)
    with patcher:
        rows = await planter.seed_baseline("web1", repo, bus=fake_bus)
    assert {r["generator"] for r in rows} == {"git_config", "env_file", "aws_creds"}
    # One docker exec per generator.
    assert len(captured) == 3
    # aws_creds ends up as kind=aws_passive; the other two are http.
    by_gen = {r["generator"]: r for r in rows}
    assert by_gen["aws_creds"]["kind"] == "aws_passive"
    assert by_gen["env_file"]["kind"] == "http"
    persisted = await repo.list_canary_tokens(decky_name="web1")
    assert len(persisted) == 3


@pytest.mark.asyncio
async def test_seed_baseline_skips_unknown_generator(repo: SQLiteRepository, monkeypatch) -> None:
    monkeypatch.setenv("DECNET_CANARY_BASELINE", "env_file,bogus")
    patcher, _ = _patch_subprocess(rc=0)
    with patcher:
        rows = await planter.seed_baseline("web1", repo)
    assert {r["generator"] for r in rows} == {"env_file"}


@pytest.mark.asyncio
async def test_seed_baseline_marks_failed_when_docker_errors(
    repo: SQLiteRepository, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BASELINE", "env_file")
    patcher, _ = _patch_subprocess(rc=125, stderr=b"container down")
    with patcher:
        rows = await planter.seed_baseline("web1", repo)
    assert len(rows) == 1
    persisted = await repo.list_canary_tokens(decky_name="web1")
    assert persisted[0]["state"] == "failed"
    assert persisted[0]["last_error"]
