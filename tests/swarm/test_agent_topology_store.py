"""Tests for :mod:`decnet.agent.topology_store`."""
from __future__ import annotations

import pathlib

import pytest

from decnet.agent.topology_store import (
    AlreadyApplied,
    TopologyStore,
    observed,
)


def _store(tmp_path: pathlib.Path) -> TopologyStore:
    return TopologyStore(tmp_path / "topology.db")


def test_idle_by_default(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    assert s.current() is None
    s.close()


def test_put_then_current(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    s.put("t1", "hash-a", {"topology": {"id": "t1"}, "lans": []})
    row = s.current()
    assert row is not None
    assert row.topology_id == "t1"
    assert row.applied_version_hash == "hash-a"
    assert row.hydrated["topology"]["id"] == "t1"
    assert row.last_error is None
    s.close()


def test_put_same_id_is_idempotent_update(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    s.put("t1", "hash-a", {"k": 1})
    s.put("t1", "hash-b", {"k": 2})
    row = s.current()
    assert row is not None
    assert row.applied_version_hash == "hash-b"
    assert row.hydrated == {"k": 2}
    s.close()


def test_put_different_id_rejected(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    s.put("t1", "hash-a", {})
    with pytest.raises(AlreadyApplied):
        s.put("t2", "hash-b", {})
    s.close()


def test_record_error_then_put_clears(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    s.put("t1", "h", {})
    s.record_error("t1", "kaboom")
    assert s.current().last_error == "kaboom"
    # Re-applying clears the error flag.
    s.put("t1", "h2", {})
    assert s.current().last_error is None
    s.close()


def test_record_error_upserts_when_no_prior_row(tmp_path: pathlib.Path) -> None:
    """Apply failure mid-materialise: put() hasn't written a row yet but
    we still want the error surfaced on GET /topology/state and the
    next heartbeat.  The marker uses empty hash so master sees drift."""
    s = _store(tmp_path)
    s.record_error("t-fail", "docker refused connection")
    row = s.current()
    assert row is not None
    assert row.topology_id == "t-fail"
    assert row.applied_version_hash == ""
    assert row.applied_at == 0
    assert row.last_error == "docker refused connection"
    s.close()


def test_record_error_then_successful_put_replaces_marker(tmp_path: pathlib.Path) -> None:
    """Once a retry succeeds, the marker row must be replaced with a
    real applied row — no stale error or empty hash left behind."""
    s = _store(tmp_path)
    s.record_error("t-retry", "first try failed")
    s.put("t-retry", "real-hash", {"topology": {"id": "t-retry"}})
    row = s.current()
    assert row.applied_version_hash == "real-hash"
    assert row.last_error is None
    assert row.applied_at > 0
    s.close()


def test_clear(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    s.put("t1", "h", {})
    s.clear("t1")
    assert s.current() is None
    # Clearing a missing id is a no-op (teardown idempotency).
    s.clear("t1")
    s.close()


def test_persists_across_reopen(tmp_path: pathlib.Path) -> None:
    s = _store(tmp_path)
    s.put("t1", "h", {"x": 1})
    s.close()
    s2 = _store(tmp_path)
    row = s2.current()
    assert row is not None
    assert row.topology_id == "t1"
    s2.close()


# -------------------------------------------------------- observed() helper


class _FakeNet:
    def __init__(self, name: str, driver: str) -> None:
        self.name = name
        self.attrs = {"Driver": driver}


class _FakeContainer:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeDocker:
    def __init__(self, nets, containers) -> None:
        self.networks = type("N", (), {"list": lambda _self: nets})()
        self.containers = type(
            "C", (), {"list": lambda _self, all=False: containers}
        )()


def test_observed_filters_by_prefix() -> None:
    nets = [
        _FakeNet("decnet-topology-abc", "bridge"),
        _FakeNet("bridge", "bridge"),
        _FakeNet("decnet-topology-xyz", "overlay"),  # wrong driver — filtered
    ]
    containers = [_FakeContainer("decnet-deaddeck"), _FakeContainer("sshd")]
    snap = observed(_FakeDocker(nets, containers))
    assert snap == {
        "bridges": ["decnet-topology-abc"],
        "containers": ["decnet-deaddeck"],
    }


def test_observed_reports_error_on_failure() -> None:
    class _Broken:
        @property
        def networks(self):
            raise RuntimeError("docker down")

    snap = observed(_Broken())
    assert "error" in snap
    assert "docker down" in snap["error"]
