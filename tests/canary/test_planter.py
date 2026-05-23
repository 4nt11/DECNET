# SPDX-License-Identifier: AGPL-3.0-or-later
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
    stdin_seen: list[bytes | None] = []

    async def _fake(*argv, **kw):
        captured.append(list(argv))
        # Capture whatever bytes the planter would stream over stdin —
        # the new contract pipes the base64 payload here instead of
        # interpolating it into the sh script.
        proc = _FakeProc(rc, b"", stderr)
        orig = proc.communicate

        async def communicate(input=None):
            stdin_seen.append(input)
            return await orig()
        proc.communicate = communicate  # type: ignore[assignment]
        return proc

    return patch.object(asyncio, "create_subprocess_exec", _fake), captured, stdin_seen


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
    patcher, captured, stdin_seen = _patch_subprocess(rc=0)
    with patcher:
        ok, err = await planter.plant(
            "web1", art, token_uuid="tok-1", repo=repo, bus=fake_bus,
        )
    assert ok is True and err is None
    assert len(captured) == 1
    argv = captured[0]
    # docker exec -i <container> sh -c <script>
    assert argv[:4] == ["docker", "exec", "-i", "web1-ssh"]
    assert argv[4:6] == ["sh", "-c"]
    script = argv[6]
    # The base64 payload is streamed via stdin, NOT interpolated into
    # the script (would blow past ARG_MAX for any non-trivial blob).
    assert stdin_seen[0] == base64.b64encode(art.content)
    assert "base64 -d > /home/admin/.aws/credentials" in script
    assert base64.b64encode(art.content).decode() not in script
    # touch -d 'YYYY-MM-DD HH:MM:SS UTC' — backdated via mtime_offset.
    m = re.search(r"touch -d '(\d{4}-\d{2}-\d{2}) ", script)
    assert m
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
    patcher, _argvs, _stdin = _patch_subprocess(rc=125, stderr=b"container not running")
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
    patcher, _argvs, _stdin = _patch_subprocess(rc=0)
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
    patcher, captured, _stdin = _patch_subprocess(rc=0)
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
    patcher, captured, _stdin = _patch_subprocess(rc=0)
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
    patcher, _argvs, _stdin = _patch_subprocess(rc=0)
    with patcher:
        rows = await planter.seed_baseline("web1", repo)
    assert {r["generator"] for r in rows} == {"env_file"}


@pytest.mark.asyncio
async def test_plant_honours_explicit_container_override(repo: SQLiteRepository) -> None:
    """``container=`` lets MazeNET callers target a non-``<name>-ssh`` container."""
    await repo.create_canary_token({
        "uuid": "tok-c", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/x",
        "callback_token": "slugC", "secret_seed": "s", "created_by": "u1",
    })
    art = CanaryArtifact(path="/x", content=b"y", generator="env_file")
    patcher, captured, _stdin = _patch_subprocess(rc=0)
    with patcher:
        ok, _err = await planter.plant(
            "web1", art, token_uuid="tok-c", repo=repo,
            container="decnet_t_abc12345_web1",
        )
    assert ok is True
    # docker exec -i <override-container> ...
    assert captured[0][3] == "decnet_t_abc12345_web1"


def test_resolve_topology_container_prefers_ssh_service() -> None:
    name = planter.resolve_topology_container(
        "abc123def456", "web1", services=["ssh", "http"],
    )
    assert name == "web1-ssh"


def test_resolve_topology_container_falls_back_to_base() -> None:
    name = planter.resolve_topology_container(
        "abc123def456789", "router", services=["dns"],
    )
    # decnet_t_<id8>_<decky_name>; matches topology.compose._container_name.
    assert name == "decnet_t_abc123de_router"


@pytest.mark.asyncio
async def test_seed_baseline_topology_iterates_deckies_and_resolves_container(
    repo: SQLiteRepository, monkeypatch
) -> None:
    """Topology seed: ssh-bearing decky → ``<name>-ssh``; bare decky → base."""
    monkeypatch.setenv("DECNET_CANARY_BASELINE", "env_file")
    topo_id = "abcdef0123456789"

    async def _fake_hydrate(_repo, _topo_id):
        assert _topo_id == topo_id
        return {
            "topology": {"id": topo_id},
            "lans": [],
            "deckies": [
                {
                    "uuid": "u1", "name": "web1",
                    "decky_config": {"name": "web1"},
                    "services": ["ssh", "http"],
                },
                {
                    "uuid": "u2", "name": "router",
                    "decky_config": {"name": "router"},
                    "services": ["dns"],
                },
            ],
            "edges": [],
        }

    import decnet.canary.planter as _planter_mod
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate", _fake_hydrate,
    )

    patcher, captured, _stdin = _patch_subprocess(rc=0)
    with patcher:
        rows = await _planter_mod.seed_baseline_topology(repo, topo_id)

    # One token per decky × one generator in the baseline.
    assert {r["decky_name"] for r in rows} == {"web1", "router"}
    # docker exec -i <container> ... — captured argv index 3 is container.
    containers = sorted(argv[3] for argv in captured)
    assert containers == ["decnet_t_abcdef01_router", "web1-ssh"]


@pytest.mark.asyncio
async def test_seed_baseline_topology_returns_empty_for_missing_topology(
    repo: SQLiteRepository, monkeypatch
) -> None:
    async def _none_hydrate(_repo, _topo_id):
        return None
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate", _none_hydrate,
    )
    rows = await planter.seed_baseline_topology(repo, "missing-id")
    assert rows == []


@pytest.mark.asyncio
async def test_seed_baseline_marks_failed_when_docker_errors(
    repo: SQLiteRepository, monkeypatch
) -> None:
    monkeypatch.setenv("DECNET_CANARY_BASELINE", "env_file")
    patcher, _argvs, _stdin = _patch_subprocess(rc=125, stderr=b"container down")
    with patcher:
        rows = await planter.seed_baseline("web1", repo)
    assert len(rows) == 1
    persisted = await repo.list_canary_tokens(decky_name="web1")
    assert persisted[0]["state"] == "failed"
    assert persisted[0]["last_error"]
