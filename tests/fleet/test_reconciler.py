# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for decnet.fleet.reconciler — pure-function reconcile pass.

Uses a fake repository (in-memory dict) and a stub docker client so the
suite never touches MySQL/SQLite or a real docker socket.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from decnet.config import DeckyConfig, DecnetConfig
from decnet.fleet.reconciler import (
    _aggregate_decky_state,
    reconcile_once,
)


# ── Fakes ─────────────────────────────────────────────────────────────────────

class FakeRepo:
    """Minimal in-memory stand-in for the fleet portion of BaseRepository."""

    def __init__(self, rows: list[dict[str, Any]] | None = None):
        self.rows = list(rows or [])
        self.upserts: list[dict] = []
        self.deletes: list[tuple[str, str]] = []
        self.state_updates: list[dict] = []

    async def list_fleet_deckies(self, *, host_uuid: str | None = None):
        return [
            r for r in self.rows
            if host_uuid is None or r.get("host_uuid") == host_uuid
        ]

    async def upsert_fleet_decky(self, data: dict[str, Any]) -> None:
        self.upserts.append(data)
        # Reflect into rows so subsequent calls see it
        self.rows = [
            r for r in self.rows
            if not (r["host_uuid"] == data["host_uuid"] and r["name"] == data["name"])
        ]
        self.rows.append(data)

    async def delete_fleet_decky(self, *, host_uuid: str, name: str) -> None:
        self.deletes.append((host_uuid, name))
        self.rows = [
            r for r in self.rows
            if not (r["host_uuid"] == host_uuid and r["name"] == name)
        ]

    async def update_fleet_decky_state(
        self, *, host_uuid: str, name: str, state: str,
        last_error: str | None = None,
    ) -> None:
        self.state_updates.append({
            "host_uuid": host_uuid, "name": name, "state": state,
        })
        for r in self.rows:
            if r["host_uuid"] == host_uuid and r["name"] == name:
                r["state"] = state


def _decky(name: str = "decky-01", ip: str = "10.0.0.10",
           services: list[str] | None = None) -> DeckyConfig:
    return DeckyConfig(
        name=name, ip=ip, services=services or ["ssh"],
        distro="debian", base_image="debian", hostname="h",
        build_base="debian:bookworm-slim", nmap_os="linux",
    )


def _config(deckies: list[DeckyConfig]) -> DecnetConfig:
    return DecnetConfig(
        mode="unihost", interface="eth0", subnet="10.0.0.0/24",
        gateway="10.0.0.1", deckies=deckies, ipvlan=False,
    )


def _state_loader(deckies: list[DeckyConfig] | None):
    """Return a fake load_state callable."""
    if deckies is None:
        return lambda: None
    return lambda: (_config(deckies), None)


def _docker_factory(container_states: dict[str, str]):
    """Return a docker client factory that yields the given container states.

    The factory's product mimics ``docker.from_env()`` enough that
    ``_collect_container_states`` can iterate ``client.containers.list(...)``.
    """
    containers = [
        type("C", (), {"name": name, "status": status})()
        for name, status in container_states.items()
    ]
    client = MagicMock()
    client.containers.list.return_value = containers
    return lambda: client


# ── _aggregate_decky_state ────────────────────────────────────────────────────

class TestAggregate:
    def test_all_running(self):
        s = _aggregate_decky_state("d", ["ssh", "http"], {
            "d-ssh": "running", "d-http": "running",
        })
        assert s == "running"

    def test_partial_running_is_degraded(self):
        s = _aggregate_decky_state("d", ["ssh", "http"], {
            "d-ssh": "running", "d-http": "exited",
        })
        assert s == "degraded"

    def test_one_service_missing_is_degraded(self):
        s = _aggregate_decky_state("d", ["ssh", "http"], {
            "d-ssh": "running",  # d-http never started
        })
        assert s == "degraded"

    def test_all_dead_is_failed(self):
        s = _aggregate_decky_state("d", ["ssh"], {"d-ssh": "exited"})
        assert s == "failed"

    def test_no_containers_is_torn_down(self):
        assert _aggregate_decky_state("d", ["ssh"], {}) == "torn_down"

    def test_underscore_in_service_name_normalized_to_dash(self):
        # The deployer creates container "<decky>-<svc>" with underscores
        # rewritten to dashes (see deployer.status()).  Aggregate must
        # follow the same convention or it'll never match.
        s = _aggregate_decky_state("d", ["smtp_relay"], {
            "d-smtp-relay": "running",
        })
        assert s == "running"


# ── reconcile_once ────────────────────────────────────────────────────────────

@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestReconcileOnce:
    @pytest.mark.anyio
    async def test_inserts_when_json_has_decky_db_does_not(self):
        repo = FakeRepo()  # DB empty
        d = _decky(name="solo", ip="10.0.0.5", services=["ssh"])
        counts = await reconcile_once(
            repo,
            load_state_fn=_state_loader([d]),
            docker_client_factory=_docker_factory({"solo-ssh": "running"}),
        )
        assert counts == {"inserted": 1, "deleted": 0, "state_updated": 0}
        assert len(repo.upserts) == 1
        u = repo.upserts[0]
        assert u["host_uuid"] == "local"
        assert u["name"] == "solo"
        assert u["services"] == ["ssh"]
        assert u["decky_ip"] == "10.0.0.5"
        assert u["state"] == "running"

    @pytest.mark.anyio
    async def test_deletes_when_db_has_decky_json_does_not(self):
        repo = FakeRepo([
            {"host_uuid": "local", "name": "ghost", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.99"},
        ])
        counts = await reconcile_once(
            repo,
            load_state_fn=lambda: None,  # no JSON state
            docker_client_factory=_docker_factory({}),
        )
        assert counts == {"inserted": 0, "deleted": 1, "state_updated": 0}
        assert repo.deletes == [("local", "ghost")]

    @pytest.mark.anyio
    async def test_updates_state_when_docker_disagrees(self):
        repo = FakeRepo([
            {"host_uuid": "local", "name": "d1", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.10"},
        ])
        d = _decky(name="d1", services=["ssh"])
        counts = await reconcile_once(
            repo,
            load_state_fn=_state_loader([d]),
            docker_client_factory=_docker_factory({"d1-ssh": "exited"}),
        )
        assert counts == {"inserted": 0, "deleted": 0, "state_updated": 1}
        assert repo.state_updates[0]["state"] == "failed"

    @pytest.mark.anyio
    async def test_no_writes_when_already_converged(self):
        repo = FakeRepo([
            {"host_uuid": "local", "name": "d1", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.10"},
        ])
        d = _decky(name="d1", services=["ssh"])
        counts = await reconcile_once(
            repo,
            load_state_fn=_state_loader([d]),
            docker_client_factory=_docker_factory({"d1-ssh": "running"}),
        )
        assert counts == {"inserted": 0, "deleted": 0, "state_updated": 0}
        assert repo.upserts == [] and repo.deletes == []
        assert repo.state_updates == []

    @pytest.mark.anyio
    async def test_skips_state_updates_when_docker_unreachable(self):
        """Docker socket failure must not torch every row to torn_down —
        the reconciler returns ``None`` from _collect_container_states and
        leaves existing DB state alone."""
        repo = FakeRepo([
            {"host_uuid": "local", "name": "d1", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.10"},
        ])
        d = _decky(name="d1", services=["ssh"])

        def broken_factory():
            raise RuntimeError("docker socket unreachable")

        counts = await reconcile_once(
            repo,
            load_state_fn=_state_loader([d]),
            docker_client_factory=broken_factory,
        )
        assert counts == {"inserted": 0, "deleted": 0, "state_updated": 0}
        assert repo.state_updates == []

    @pytest.mark.anyio
    async def test_host_uuid_scoping_protects_peer_rows(self):
        """A reconcile on host A must NOT delete rows belonging to host B."""
        repo = FakeRepo([
            {"host_uuid": "host-a", "name": "d1", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.10"},
            {"host_uuid": "host-b", "name": "d2", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.1.10"},
        ])
        # Reconciling on host-a with no JSON state
        counts = await reconcile_once(
            repo,
            host_uuid="host-a",
            load_state_fn=lambda: None,
            docker_client_factory=_docker_factory({}),
        )
        assert counts["deleted"] == 1
        # Only host-a's row was touched
        assert repo.deletes == [("host-a", "d1")]
        # host-b's row survives
        assert any(r["host_uuid"] == "host-b" for r in repo.rows)

    @pytest.mark.anyio
    async def test_publishes_decky_state_on_transitions(self):
        """When *bus* is provided, every insert/delete/state-change must
        publish on ``decky.<host_uuid:name>.state``."""
        from decnet.bus.fake import FakeBus
        bus = FakeBus()
        await bus.connect()

        published: list = []

        async def collect():
            async with bus.subscribe("decky.>") as sub:
                async for ev in sub:
                    published.append(ev)
                    if len(published) >= 3:
                        return

        try:
            collector = asyncio.create_task(collect())
            await asyncio.sleep(0)  # let subscription register

            repo = FakeRepo([
                # An existing row that will be deleted (not in JSON).
                {"host_uuid": "local", "name": "ghost", "services": ["ssh"],
                 "state": "running", "decky_ip": "10.0.0.99"},
                # An existing row whose state will flip running → failed.
                {"host_uuid": "local", "name": "d-flip", "services": ["ssh"],
                 "state": "running", "decky_ip": "10.0.0.20"},
            ])
            json_deckies = [
                _decky(name="d-new", ip="10.0.0.30", services=["http"]),
                _decky(name="d-flip", ip="10.0.0.20", services=["ssh"]),
            ]
            await reconcile_once(
                repo,
                load_state_fn=_state_loader(json_deckies),
                docker_client_factory=_docker_factory({
                    "d-new-http": "running",
                    "d-flip-ssh": "exited",
                }),
                bus=bus,
            )
            await asyncio.wait_for(collector, timeout=2.0)
        finally:
            await bus.close()

        topics = sorted(ev.topic for ev in published)
        assert topics == [
            "decky.local:d-flip.state",
            "decky.local:d-new.state",
            "decky.local:ghost.state",
        ]
        by_name = {ev.payload["name"]: ev.payload for ev in published}
        assert by_name["d-new"]["transition"] == "inserted"
        assert by_name["d-new"]["state"] == "running"
        assert by_name["ghost"]["transition"] == "deleted"
        assert by_name["ghost"]["state"] == "torn_down"
        assert by_name["d-flip"]["transition"] == "state_changed"
        assert by_name["d-flip"]["state"] == "failed"
        assert by_name["d-flip"]["previous_state"] == "running"

    @pytest.mark.anyio
    async def test_no_bus_publish_when_already_converged(self):
        """Quiet ticks must not publish — otherwise every 30s the bus
        floods with no-op events."""
        from decnet.bus.fake import FakeBus
        bus = FakeBus()
        await bus.connect()
        try:
            published: list = []

            async def collect():
                async with bus.subscribe("decky.>") as sub:
                    async for ev in sub:
                        published.append(ev)

            collector = asyncio.create_task(collect())
            await asyncio.sleep(0)

            repo = FakeRepo([
                {"host_uuid": "local", "name": "d1", "services": ["ssh"],
                 "state": "running", "decky_ip": "10.0.0.10"},
            ])
            d = _decky(name="d1", services=["ssh"])
            await reconcile_once(
                repo,
                load_state_fn=_state_loader([d]),
                docker_client_factory=_docker_factory({"d1-ssh": "running"}),
                bus=bus,
            )
            await asyncio.sleep(0.1)  # give the bus a window to deliver
            collector.cancel()
        finally:
            await bus.close()

        assert published == []

    @pytest.mark.anyio
    async def test_combined_drift_in_one_pass(self):
        """JSON has new decky AND DB has stale decky AND third decky's
        container died — all three converge in a single tick."""
        repo = FakeRepo([
            {"host_uuid": "local", "name": "stale", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.99"},
            {"host_uuid": "local", "name": "d-existing", "services": ["ssh"],
             "state": "running", "decky_ip": "10.0.0.20"},
        ])
        json_deckies = [
            _decky(name="d-new", ip="10.0.0.30", services=["http"]),
            _decky(name="d-existing", ip="10.0.0.20", services=["ssh"]),
        ]
        counts = await reconcile_once(
            repo,
            load_state_fn=_state_loader(json_deckies),
            docker_client_factory=_docker_factory({
                "d-new-http": "running",
                "d-existing-ssh": "exited",  # crashed
            }),
        )
        assert counts == {"inserted": 1, "deleted": 1, "state_updated": 1}
        names_inserted = [u["name"] for u in repo.upserts]
        assert "d-new" in names_inserted
        assert ("local", "stale") in repo.deletes
        assert any(s["name"] == "d-existing" and s["state"] == "failed"
                   for s in repo.state_updates)
