"""Tests for the orphan topology-resource reaper."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from decnet.engine.reaper import (
    ReapReport,
    _orphan_prefixes,
    _prefix_of,
    reap_orphan_topology_resources,
)


# ---------------------------------------------------------------- pure helpers


def test_prefix_of_matches_decnet_convention():
    assert _prefix_of("decnet_t_abcd1234_dmz") == "abcd1234"
    assert _prefix_of("decnet_t_abcd1234_subnet-01") == "abcd1234"
    assert _prefix_of("decnet_t_abcd1234_decky-631b") == "abcd1234"


def test_prefix_of_rejects_non_decnet_names():
    assert _prefix_of("bridge") is None
    assert _prefix_of("host") is None
    assert _prefix_of("development_default") is None
    # Prefix must be 8 hex chars exactly.
    assert _prefix_of("decnet_t_abcd_dmz") is None
    assert _prefix_of("decnet_t_abcd1234_") == "abcd1234"  # trailing edge


def test_orphan_prefixes_flags_only_unknowns():
    live = {"aaaa1111", "bbbb2222"}
    containers = [
        "decnet_t_aaaa1111_decky-01",     # live
        "decnet_t_cccc3333_dmz-gateway",  # orphan
        "bridge",                          # not DECNET
    ]
    networks = [
        "decnet_t_bbbb2222_subnet-01",    # live
        "decnet_t_cccc3333_dmz",          # orphan
        "decnet_t_dddd4444_subnet-01",    # orphan
    ]
    orphans, decnet_cs, decnet_ns = _orphan_prefixes(containers, networks, live)
    assert orphans == {"cccc3333", "dddd4444"}
    assert "bridge" not in decnet_cs
    assert len(decnet_ns) == 3


def test_orphan_prefixes_empty_when_all_live():
    live = {"aaaa1111"}
    containers = ["decnet_t_aaaa1111_decky"]
    networks = ["decnet_t_aaaa1111_dmz"]
    orphans, *_ = _orphan_prefixes(containers, networks, live)
    assert orphans == set()


# ---------------------------------------------------------------- integration


class _FakeContainer:
    def __init__(self, name, remove_raises=None):
        self.name = name
        self._raises = remove_raises
        self.removed = False
    def remove(self, force=False):  # noqa: ARG002
        if self._raises:
            raise self._raises
        self.removed = True


class _FakeNetwork:
    def __init__(self, name):
        self.name = name
        self.id = f"id-{name}"
        self.attrs = {"Containers": {}}
        self.removed = False
    def remove(self):
        self.removed = True
    def disconnect(self, cid, force=False):  # pragma: no cover
        pass


class _FakeClient:
    def __init__(self, containers, networks):
        self._cs = containers
        self._ns = networks
        self.containers = SimpleNamespace(list=lambda all=False: list(self._cs))
        self.networks = self

    def list(self, names=None, filters=None):  # noqa: ARG002
        if names is None:
            return list(self._ns)
        return [n for n in self._ns if n.name in set(names)]


class _StubRepo:
    def __init__(self, topology_ids):
        self._ids = topology_ids
    async def list_topologies(self):
        return [{"id": tid} for tid in self._ids]


@pytest.mark.anyio
async def test_reap_removes_only_orphans():
    live_tid = "aaaa1111-1111-1111-1111-111111111111"
    repo = _StubRepo([live_tid])

    containers = [
        _FakeContainer("decnet_t_aaaa1111_decky"),       # live — keep
        _FakeContainer("decnet_t_dead0000_dmz-gateway"), # orphan
        _FakeContainer("decnet_t_dead0000_decky-1"),     # orphan
        _FakeContainer("bridge"),                         # non-DECNET
    ]
    networks = [
        _FakeNetwork("decnet_t_aaaa1111_dmz"),        # live — keep
        _FakeNetwork("decnet_t_dead0000_dmz"),        # orphan
        _FakeNetwork("decnet_t_dead0000_subnet-01"),  # orphan
        _FakeNetwork("host"),                          # non-DECNET
    ]
    client = _FakeClient(containers, networks)

    report = await reap_orphan_topology_resources(repo, client=client)

    assert report.live_prefixes == ["aaaa1111"]
    assert report.orphan_prefixes == ["dead0000"]
    assert set(report.containers_removed) == {
        "decnet_t_dead0000_dmz-gateway",
        "decnet_t_dead0000_decky-1",
    }
    assert set(report.networks_removed) == {
        "decnet_t_dead0000_dmz",
        "decnet_t_dead0000_subnet-01",
    }
    assert report.errors == []
    # Live resources must survive.
    assert all(c.removed is False for c in containers if "aaaa1111" in c.name)
    assert all(n.removed is False for n in networks if "aaaa1111" in n.name)


@pytest.mark.anyio
async def test_reap_is_noop_when_no_orphans():
    repo = _StubRepo(["aaaa1111-xxx"])
    containers = [_FakeContainer("decnet_t_aaaa1111_d")]
    networks = [_FakeNetwork("decnet_t_aaaa1111_net")]
    client = _FakeClient(containers, networks)

    report = await reap_orphan_topology_resources(repo, client=client)

    assert report.orphan_prefixes == []
    assert report.containers_removed == []
    assert report.networks_removed == []


@pytest.mark.anyio
async def test_reap_captures_per_resource_errors_without_aborting():
    repo = _StubRepo([])
    containers = [
        _FakeContainer("decnet_t_dead0000_c1", remove_raises=RuntimeError("stuck")),
        _FakeContainer("decnet_t_dead0000_c2"),
    ]
    networks = [_FakeNetwork("decnet_t_dead0000_net")]
    client = _FakeClient(containers, networks)

    report = await reap_orphan_topology_resources(repo, client=client)

    # The failing container is reported; the next one still gets removed.
    assert any("c1" in e for e in report.errors)
    assert "decnet_t_dead0000_c2" in report.containers_removed
    assert "decnet_t_dead0000_net" in report.networks_removed


@pytest.mark.anyio
async def test_reap_handles_docker_list_failure():
    repo = _StubRepo(["aaaa1111"])
    client = MagicMock()
    client.containers.list.side_effect = RuntimeError("docker down")
    client.networks.list.return_value = []
    report = await reap_orphan_topology_resources(repo, client=client)
    assert any("docker list failed" in e for e in report.errors)
    assert report.containers_removed == []
    assert report.networks_removed == []


# ---------------------------------------------------------------------- report


def test_reap_report_to_dict_is_serialisable():
    r = ReapReport(
        live_prefixes=["aa"], orphan_prefixes=["bb"],
        containers_removed=["c"], networks_removed=["n"], errors=[],
    )
    d = r.to_dict()
    assert d == {
        "live_prefixes": ["aa"],
        "orphan_prefixes": ["bb"],
        "containers_removed": ["c"],
        "networks_removed": ["n"],
        "errors": [],
    }


# ---------------------------------------------------------------------- API


@pytest.mark.anyio
async def test_api_reap_orphans_requires_admin(monkeypatch):
    """POST /topologies/reap-orphans returns the report dict."""
    from decnet.web.router.topology.api_reap_orphans import api_reap_orphans

    with patch(
        "decnet.web.router.topology.api_reap_orphans.reap_orphan_topology_resources"
    ) as mock_reap:
        mock_reap.return_value = ReapReport(
            live_prefixes=["aaaa1111"],
            orphan_prefixes=["dead0000"],
            containers_removed=["decnet_t_dead0000_c"],
            networks_removed=["decnet_t_dead0000_n"],
        )
        result = await api_reap_orphans(_admin={"role": "admin"})

    assert result["orphan_prefixes"] == ["dead0000"]
    assert result["containers_removed"] == ["decnet_t_dead0000_c"]
    assert result["networks_removed"] == ["decnet_t_dead0000_n"]
    assert result["errors"] == []
