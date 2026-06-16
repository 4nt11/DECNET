# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI `decnet swarm {enroll,list,decommission}` + `deploy --mode swarm`.

Controller HTTP is stubbed via monkeypatching `_http_request`; we aren't
testing the controller (that has its own test file) or httpx itself. We
*are* testing: arg parsing, URL construction, round-robin sharding of
deckies, bundle file output, error paths when the controller rejects.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from typer.testing import CliRunner

from decnet import cli as cli_mod
from decnet.cli import app, deploy as cli_deploy, utils as cli_utils


runner = CliRunner()


class _FakeResp:
    def __init__(self, payload: Any, status: int = 200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload) if not isinstance(payload, str) else payload

    def json(self) -> Any:
        return self._payload


class _HttpStub(list):
    """Both a call log and a scripted-reply registry."""
    def __init__(self) -> None:
        super().__init__()
        self.script: dict[tuple[str, str], _FakeResp] = {}


@pytest.fixture
def http_stub(monkeypatch: pytest.MonkeyPatch) -> _HttpStub:
    calls = _HttpStub()

    def _fake(method, url, *, json_body=None, timeout=30.0):
        calls.append((method, url, json_body))
        for (m, suffix), resp in calls.script.items():
            if m == method and url.endswith(suffix):
                return resp
        raise AssertionError(f"Unscripted HTTP call: {method} {url}")

    monkeypatch.setattr(cli_utils, "_http_request", _fake)
    return calls


# ------------------------------------------------------------- swarm list


def test_swarm_list_empty(http_stub) -> None:
    http_stub.script[("GET", "/swarm/hosts")] = _FakeResp([])
    result = runner.invoke(app, ["swarm", "list"])
    assert result.exit_code == 0
    assert "No workers" in result.output


def test_swarm_list_with_rows(http_stub) -> None:
    http_stub.script[("GET", "/swarm/hosts")] = _FakeResp([
        {"uuid": "u1", "name": "decky01", "address": "10.0.0.1",
         "agent_port": 8765, "status": "active", "last_heartbeat": None,
         "enrolled_at": "2026-04-18T00:00:00Z", "notes": None,
         "client_cert_fingerprint": "ab:cd"},
    ])
    result = runner.invoke(app, ["swarm", "list"])
    assert result.exit_code == 0
    assert "decky01" in result.output
    assert "10.0.0.1" in result.output


def test_swarm_list_passes_status_filter(http_stub) -> None:
    http_stub.script[("GET", "/swarm/hosts?host_status=active")] = _FakeResp([])
    result = runner.invoke(app, ["swarm", "list", "--status", "active"])
    assert result.exit_code == 0
    # last call URL ended with the filter suffix
    assert http_stub[-1][1].endswith("/swarm/hosts?host_status=active")


# ------------------------------------------------------------- swarm enroll


def test_swarm_enroll_writes_bundle(http_stub, tmp_path: pathlib.Path) -> None:
    http_stub.script[("POST", "/swarm/enroll")] = _FakeResp({
        "host_uuid": "u-123", "name": "decky01", "address": "10.0.0.1",
        "agent_port": 8765, "fingerprint": "de:ad:be:ef",
        "ca_cert_pem": "CA-PEM", "worker_cert_pem": "CRT-PEM",
        "worker_key_pem": "KEY-PEM",
    })
    out = tmp_path / "bundle"
    result = runner.invoke(app, [
        "swarm", "enroll",
        "--name", "decky01", "--address", "10.0.0.1",
        "--sans", "decky01.lan,10.0.0.1",
        "--out-dir", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert (out / "ca.crt").read_text() == "CA-PEM"
    assert (out / "worker.crt").read_text() == "CRT-PEM"
    assert (out / "worker.key").read_text() == "KEY-PEM"
    # SANs were forwarded in the JSON body.
    _, _, body = http_stub[0]
    assert body["sans"] == ["decky01.lan", "10.0.0.1"]


# ------------------------------------------------------------- swarm check


def test_swarm_check_prints_table(http_stub) -> None:
    http_stub.script[("POST", "/swarm/check")] = _FakeResp({
        "results": [
            {"host_uuid": "u-a", "name": "decky01", "address": "10.0.0.1",
             "reachable": True, "detail": {"status": "ok"}},
            {"host_uuid": "u-b", "name": "decky02", "address": "10.0.0.2",
             "reachable": False, "detail": "connection refused"},
        ]
    })
    result = runner.invoke(app, ["swarm", "check"])
    assert result.exit_code == 0, result.output
    assert "decky01" in result.output
    assert "decky02" in result.output
    # Both reachable=true and reachable=false render.
    assert "yes" in result.output.lower()
    assert "no" in result.output.lower()


def test_swarm_check_empty(http_stub) -> None:
    http_stub.script[("POST", "/swarm/check")] = _FakeResp({"results": []})
    result = runner.invoke(app, ["swarm", "check"])
    assert result.exit_code == 0
    assert "No workers" in result.output


def test_swarm_check_json_output(http_stub) -> None:
    http_stub.script[("POST", "/swarm/check")] = _FakeResp({
        "results": [
            {"host_uuid": "u-a", "name": "decky01", "address": "10.0.0.1",
             "reachable": True, "detail": {"status": "ok"}},
        ]
    })
    result = runner.invoke(app, ["swarm", "check", "--json"])
    assert result.exit_code == 0
    # JSON mode emits structured output, not the rich table.
    assert '"reachable"' in result.output
    assert '"decky01"' in result.output


# ------------------------------------------------------------- swarm deckies


def test_swarm_deckies_empty(http_stub) -> None:
    http_stub.script[("GET", "/swarm/deckies")] = _FakeResp([])
    result = runner.invoke(app, ["swarm", "deckies"])
    assert result.exit_code == 0, result.output
    assert "No deckies" in result.output


def test_swarm_deckies_renders_table(http_stub) -> None:
    http_stub.script[("GET", "/swarm/deckies")] = _FakeResp([
        {"decky_name": "decky-01", "host_uuid": "u-1", "host_name": "w1",
         "host_address": "10.0.0.1", "host_status": "active",
         "services": ["ssh"], "state": "running", "last_error": None,
         "compose_hash": None, "updated_at": "2026-04-18T00:00:00Z"},
        {"decky_name": "decky-02", "host_uuid": "u-2", "host_name": "w2",
         "host_address": "10.0.0.2", "host_status": "active",
         "services": ["smb", "ssh"], "state": "failed", "last_error": "boom",
         "compose_hash": None, "updated_at": "2026-04-18T00:00:00Z"},
    ])
    result = runner.invoke(app, ["swarm", "deckies"])
    assert result.exit_code == 0, result.output
    assert "decky-01" in result.output
    assert "decky-02" in result.output
    assert "w1" in result.output and "w2" in result.output
    assert "smb,ssh" in result.output


def test_swarm_deckies_json_output(http_stub) -> None:
    http_stub.script[("GET", "/swarm/deckies")] = _FakeResp([
        {"decky_name": "decky-01", "host_uuid": "u-1", "host_name": "w1",
         "host_address": "10.0.0.1", "host_status": "active",
         "services": ["ssh"], "state": "running", "last_error": None,
         "compose_hash": None, "updated_at": "2026-04-18T00:00:00Z"},
    ])
    result = runner.invoke(app, ["swarm", "deckies", "--json"])
    assert result.exit_code == 0
    assert '"decky_name"' in result.output
    assert '"decky-01"' in result.output


def test_swarm_deckies_filter_by_host_name_looks_up_uuid(http_stub) -> None:
    http_stub.script[("GET", "/swarm/hosts")] = _FakeResp([
        {"uuid": "u-x", "name": "w1"},
    ])
    http_stub.script[("GET", "/swarm/deckies?host_uuid=u-x")] = _FakeResp([])
    result = runner.invoke(app, ["swarm", "deckies", "--host", "w1"])
    assert result.exit_code == 0
    assert http_stub[-1][1].endswith("/swarm/deckies?host_uuid=u-x")


def test_swarm_deckies_filter_by_state(http_stub) -> None:
    http_stub.script[("GET", "/swarm/deckies?state=failed")] = _FakeResp([])
    result = runner.invoke(app, ["swarm", "deckies", "--state", "failed"])
    assert result.exit_code == 0
    assert http_stub[-1][1].endswith("/swarm/deckies?state=failed")


# ------------------------------------------------------------- swarm decommission


def test_swarm_decommission_by_name_looks_up_uuid(http_stub) -> None:
    http_stub.script[("GET", "/swarm/hosts")] = _FakeResp([
        {"uuid": "u-x", "name": "decky02"},
    ])
    http_stub.script[("DELETE", "/swarm/hosts/u-x")] = _FakeResp({}, status=204)
    result = runner.invoke(app, ["swarm", "decommission", "--name", "decky02", "--yes"])
    assert result.exit_code == 0, result.output
    methods = [c[0] for c in http_stub]
    assert methods == ["GET", "DELETE"]


def test_swarm_decommission_name_not_found(http_stub) -> None:
    http_stub.script[("GET", "/swarm/hosts")] = _FakeResp([])
    result = runner.invoke(app, ["swarm", "decommission", "--name", "ghost", "--yes"])
    assert result.exit_code == 1
    assert "No enrolled worker" in result.output


def test_swarm_decommission_requires_identifier() -> None:
    result = runner.invoke(app, ["swarm", "decommission", "--yes"])
    assert result.exit_code == 2


# ------------------------------------------------------------- deploy --mode swarm


def test_deploy_swarm_round_robins_and_posts(http_stub, monkeypatch: pytest.MonkeyPatch) -> None:
    """deploy --mode swarm fetches hosts, assigns host_uuid round-robin,
    POSTs to /swarm/deploy with the sharded config."""
    # Two enrolled workers, zero active.
    http_stub.script[("GET", "/swarm/hosts?host_status=enrolled")] = _FakeResp([
        {"uuid": "u-a", "name": "A", "address": "10.0.0.1", "agent_port": 8765,
         "status": "enrolled"},
        {"uuid": "u-b", "name": "B", "address": "10.0.0.2", "agent_port": 8765,
         "status": "enrolled"},
    ])
    http_stub.script[("GET", "/swarm/hosts?host_status=active")] = _FakeResp([])
    http_stub.script[("POST", "/swarm/deploy")] = _FakeResp({
        "results": [
            {"host_uuid": "u-a", "host_name": "A", "ok": True, "detail": {"status": "ok"}},
            {"host_uuid": "u-b", "host_name": "B", "ok": True, "detail": {"status": "ok"}},
        ],
    })

    # Stub network detection so we don't need root / real NICs.
    monkeypatch.setattr(cli_deploy, "detect_interface", lambda: "eth0")
    monkeypatch.setattr(cli_deploy, "detect_subnet", lambda _iface: ("10.0.0.0/24", "10.0.0.254"))
    monkeypatch.setattr(cli_deploy, "get_host_ip", lambda _iface: "10.0.0.100")

    result = runner.invoke(app, [
        "deploy", "--mode", "swarm", "--deckies", "3",
        "--services", "ssh", "--dry-run",
    ])
    assert result.exit_code == 0, result.output

    # Find the POST /swarm/deploy body and confirm round-robin sharding.
    post = next(c for c in http_stub if c[0] == "POST" and c[1].endswith("/swarm/deploy"))
    body = post[2]
    uuids = [d["host_uuid"] for d in body["config"]["deckies"]]
    assert uuids == ["u-a", "u-b", "u-a"]
    assert body["dry_run"] is True


def test_deploy_swarm_fails_if_no_workers(http_stub, monkeypatch: pytest.MonkeyPatch) -> None:
    http_stub.script[("GET", "/swarm/hosts?host_status=enrolled")] = _FakeResp([])
    http_stub.script[("GET", "/swarm/hosts?host_status=active")] = _FakeResp([])
    monkeypatch.setattr(cli_deploy, "detect_interface", lambda: "eth0")
    monkeypatch.setattr(cli_deploy, "detect_subnet", lambda _iface: ("10.0.0.0/24", "10.0.0.254"))
    monkeypatch.setattr(cli_deploy, "get_host_ip", lambda _iface: "10.0.0.100")

    result = runner.invoke(app, [
        "deploy", "--mode", "swarm", "--deckies", "2",
        "--services", "ssh", "--dry-run",
    ])
    assert result.exit_code == 1
    assert "No enrolled workers" in result.output
