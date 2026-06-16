# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI `decnet swarm update` — target resolution, tarring, push aggregation.

The UpdaterClient is stubbed: we are testing the CLI's orchestration, not
the wire protocol (that has test_updater_app.py and UpdaterClient round-
trips live under test_swarm_api.py integration).
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from typer.testing import CliRunner

from decnet import cli as cli_mod
from decnet.cli import app, utils as cli_utils


runner = CliRunner()


class _FakeResp:
    def __init__(self, payload: Any, status: int = 200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload) if not isinstance(payload, str) else payload
        self.content = self.text.encode()

    def json(self) -> Any:
        return self._payload


@pytest.fixture
def http_stub(monkeypatch: pytest.MonkeyPatch) -> dict:
    state: dict = {"hosts": []}

    def _fake(method, url, *, json_body=None, timeout=30.0):
        if method == "GET" and url.endswith("/swarm/hosts"):
            return _FakeResp(state["hosts"])
        raise AssertionError(f"Unscripted HTTP call: {method} {url}")

    monkeypatch.setattr(cli_utils, "_http_request", _fake)
    return state


class _StubUpdaterClient:
    """Mirrors UpdaterClient's async-context-manager surface."""
    instances: list["_StubUpdaterClient"] = []
    behavior: dict[str, Any] = {}

    def __init__(self, host, *, updater_port: int = 8766, **_: Any):
        self.host = host
        self.port = updater_port
        self.calls: list[str] = []
        _StubUpdaterClient.instances.append(self)

    async def __aenter__(self) -> "_StubUpdaterClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def update(self, tarball: bytes, sha: str = "") -> _FakeResp:
        self.calls.append("update")
        return _StubUpdaterClient.behavior.get(
            self.host.get("name"),
            _FakeResp({"status": "updated", "release": {"sha": sha}}, 200),
        )

    async def update_self(self, tarball: bytes, sha: str = "") -> _FakeResp:
        self.calls.append("update_self")
        return _FakeResp({"status": "self_update_queued"}, 200)


@pytest.fixture
def stub_updater(monkeypatch: pytest.MonkeyPatch):
    _StubUpdaterClient.instances.clear()
    _StubUpdaterClient.behavior.clear()
    monkeypatch.setattr("decnet.swarm.updater_client.UpdaterClient", _StubUpdaterClient)
    # Also patch the module-level import inside cli.py's swarm_update closure.
    import decnet.cli  # noqa: F401
    return _StubUpdaterClient


def _mk_source_tree(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "src"
    root.mkdir()
    (root / "decnet").mkdir()
    (root / "decnet" / "a.py").write_text("x = 1")
    return root


# ------------------------------------------------------------- arg validation

def test_update_requires_host_or_all(http_stub) -> None:
    r = runner.invoke(app, ["swarm", "update"])
    assert r.exit_code == 2


def test_update_host_and_all_are_mutex(http_stub) -> None:
    r = runner.invoke(app, ["swarm", "update", "--host", "w1", "--all"])
    assert r.exit_code == 2


def test_update_unknown_host_exits_1(http_stub) -> None:
    http_stub["hosts"] = [{"uuid": "u1", "name": "other", "address": "10.0.0.1", "status": "active"}]
    r = runner.invoke(app, ["swarm", "update", "--host", "nope"])
    assert r.exit_code == 1
    assert "No enrolled worker" in r.output


# ---------------------------------------------------------------- happy paths

def test_update_single_host(http_stub, stub_updater, tmp_path: pathlib.Path) -> None:
    http_stub["hosts"] = [
        {"uuid": "u1", "name": "w1", "address": "10.0.0.1", "status": "active"},
        {"uuid": "u2", "name": "w2", "address": "10.0.0.2", "status": "active"},
    ]
    root = _mk_source_tree(tmp_path)
    r = runner.invoke(app, ["swarm", "update", "--host", "w1", "--root", str(root)])
    assert r.exit_code == 0, r.output
    assert "w1" in r.output
    # Only w1 got a client; w2 is untouched.
    names = [c.host["name"] for c in stub_updater.instances]
    assert names == ["w1"]


def test_update_all_skips_decommissioned(http_stub, stub_updater, tmp_path: pathlib.Path) -> None:
    http_stub["hosts"] = [
        {"uuid": "u1", "name": "w1", "address": "10.0.0.1", "status": "active"},
        {"uuid": "u2", "name": "w2", "address": "10.0.0.2", "status": "decommissioned"},
        {"uuid": "u3", "name": "w3", "address": "10.0.0.3", "status": "enrolled"},
    ]
    root = _mk_source_tree(tmp_path)
    r = runner.invoke(app, ["swarm", "update", "--all", "--root", str(root)])
    assert r.exit_code == 0, r.output
    hit = sorted(c.host["name"] for c in stub_updater.instances)
    assert hit == ["w1", "w3"]


def test_update_include_self_calls_both(
    http_stub, stub_updater, tmp_path: pathlib.Path,
) -> None:
    http_stub["hosts"] = [{"uuid": "u1", "name": "w1", "address": "10.0.0.1", "status": "active"}]
    root = _mk_source_tree(tmp_path)
    r = runner.invoke(app, ["swarm", "update", "--all", "--root", str(root), "--include-self"])
    assert r.exit_code == 0
    assert stub_updater.instances[0].calls == ["update", "update_self"]


# ------------------------------------------------------------- failure modes

def test_update_rollback_status_409_flags_failure(
    http_stub, stub_updater, tmp_path: pathlib.Path,
) -> None:
    http_stub["hosts"] = [{"uuid": "u1", "name": "w1", "address": "10.0.0.1", "status": "active"}]
    _StubUpdaterClient.behavior["w1"] = _FakeResp(
        {"detail": {"error": "probe failed", "rolled_back": True}},
        status=409,
    )
    root = _mk_source_tree(tmp_path)
    r = runner.invoke(app, ["swarm", "update", "--all", "--root", str(root)])
    assert r.exit_code == 1
    assert "rolled-back" in r.output


def test_update_include_self_skipped_when_agent_update_failed(
    http_stub, stub_updater, tmp_path: pathlib.Path,
) -> None:
    http_stub["hosts"] = [{"uuid": "u1", "name": "w1", "address": "10.0.0.1", "status": "active"}]
    _StubUpdaterClient.behavior["w1"] = _FakeResp(
        {"detail": {"error": "pip failed"}}, status=500,
    )
    root = _mk_source_tree(tmp_path)
    r = runner.invoke(app, ["swarm", "update", "--all", "--root", str(root), "--include-self"])
    assert r.exit_code == 1
    # update_self must NOT have been called — agent update failed.
    assert stub_updater.instances[0].calls == ["update"]


# --------------------------------------------------------------------- dry run

def test_update_dry_run_does_not_call_updater(
    http_stub, stub_updater, tmp_path: pathlib.Path,
) -> None:
    http_stub["hosts"] = [{"uuid": "u1", "name": "w1", "address": "10.0.0.1", "status": "active"}]
    root = _mk_source_tree(tmp_path)
    r = runner.invoke(app, ["swarm", "update", "--all", "--root", str(root), "--dry-run"])
    assert r.exit_code == 0
    assert stub_updater.instances == []
    assert "dry-run" in r.output.lower()
