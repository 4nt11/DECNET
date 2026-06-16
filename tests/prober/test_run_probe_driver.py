# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the _run_probe generic driver."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from decnet.prober.base import ActiveProbe, ActiveProbeMeta
from decnet.prober.worker import _run_probe


@pytest.fixture(autouse=True)
def _restore_registry():
    snapshot = dict(ActiveProbeMeta._registry)
    yield
    ActiveProbeMeta._registry.clear()
    ActiveProbeMeta._registry.update(snapshot)


def _make_probe(
    probe_name: str = "test_probe",
    default_ports: list[int] | None = None,
    run_return: dict[str, Any] | None = None,
    run_side_effect: Exception | None = None,
    rotation_type: str | None = "test",
    rotation_hash_key: str | None = "hash",
) -> ActiveProbe:
    """Build a concrete ActiveProbe subclass for testing and return an instance."""

    _pname = probe_name
    _ports = default_ports or [1234]
    _result = run_return
    _exc = run_side_effect
    _rtype = rotation_type
    _rkey = rotation_hash_key

    class _TestProbe(ActiveProbe):
        probe_name = _pname  # type: ignore[assignment]
        default_ports = _ports  # type: ignore[assignment]
        event_type = f"{_pname}_event"
        rotation_type = _rtype  # type: ignore[assignment]
        rotation_hash_key = _rkey
        priority = 100

        def run(self, ip: str, port: int, timeout: float) -> dict[str, Any] | None:
            if _exc is not None:
                raise _exc
            return _result

        def syslog_fields(self, ip: str, port: int, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
            return {"hash": result.get("hash", "")}, f"{_pname} {ip}:{port}"

        def publish_payload(self, ip: str, port: int, result: dict[str, Any]) -> dict[str, Any]:
            return {"attacker_ip": ip, "port": port, "hash": result.get("hash", "")}

    return _TestProbe()


class TestRunProbeDedup:

    def test_skips_already_probed_port(self, tmp_path: Path):
        probe = _make_probe(default_ports=[80, 443], run_return={"hash": "abc"})
        ip_probed: dict[str, set[int]] = {"test_probe": {80}}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert 80 in ip_probed["test_probe"]  # was already there
        assert 443 in ip_probed["test_probe"]  # newly probed

    def test_initializes_done_set_if_missing(self, tmp_path: Path):
        probe = _make_probe(default_ports=[22], run_return=None)
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert "test_probe" in ip_probed
        assert 22 in ip_probed["test_probe"]


class TestRunProbeSuccessPath:

    def test_writes_event_on_success(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return={"hash": "deadbeef"})
        ip_probed: dict[str, set[int]] = {}
        json_path = tmp_path / "events.json"

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "events.log", json_path,
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert json_path.exists()
        record = json.loads(json_path.read_text().strip())
        assert record["event_type"] == "test_probe_event"
        assert record["fields"]["target_ip"] == "1.2.3.4"
        assert record["fields"]["target_port"] == "443"
        assert record["fields"]["hash"] == "deadbeef"

    def test_calls_publish_fn_on_success(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return={"hash": "cafebabe"})
        published: list[tuple[str, dict]] = []
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=lambda k, v: published.append((k, v)),
                   record_rotation=None)

        assert len(published) == 1
        assert published[0][0] == "test_probe"
        assert published[0][1]["attacker_ip"] == "1.2.3.4"
        assert published[0][1]["hash"] == "cafebabe"

    def test_calls_record_rotation_when_configured(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return={"hash": "rotateme"},
                            rotation_type="test", rotation_hash_key="hash")
        mock_rotation = MagicMock()
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=mock_rotation)

        mock_rotation.assert_called_once_with("1.2.3.4", 443, "test", "rotateme")

    def test_skips_rotation_when_rotation_type_none(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return={"hash": "x"},
                            rotation_type=None, rotation_hash_key=None)
        mock_rotation = MagicMock()
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=mock_rotation)

        mock_rotation.assert_not_called()

    def test_skips_rotation_when_rotation_hash_key_none(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return={"hash": "x"},
                            rotation_type="test", rotation_hash_key=None)
        mock_rotation = MagicMock()
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=mock_rotation)

        mock_rotation.assert_not_called()


class TestRunProbeNoneResult:

    def test_none_suppresses_event(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return=None)
        ip_probed: dict[str, set[int]] = {}
        json_path = tmp_path / "events.json"

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "events.log", json_path,
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert 443 in ip_probed["test_probe"]
        assert not json_path.exists()

    def test_none_suppresses_publish(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443], run_return=None)
        published: list = []
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=lambda k, v: published.append((k, v)),
                   record_rotation=None)

        assert len(published) == 0


class TestRunProbeExceptionPath:

    def test_exception_marks_port_done(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443],
                            run_side_effect=OSError("Connection refused"))
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert 443 in ip_probed["test_probe"]

    def test_exception_writes_prober_error_event(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443],
                            run_side_effect=OSError("refused"))
        ip_probed: dict[str, set[int]] = {}
        json_path = tmp_path / "events.json"

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "events.log", json_path,
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert json_path.exists()
        record = json.loads(json_path.read_text().strip())
        assert record["event_type"] == "prober_error"
        assert record["fields"]["target_ip"] == "1.2.3.4"
        assert "refused" in record["fields"]["error"]

    def test_exception_does_not_publish(self, tmp_path: Path):
        probe = _make_probe(default_ports=[443],
                            run_side_effect=RuntimeError("boom"))
        published: list = []
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=lambda k, v: published.append((k, v)),
                   record_rotation=None)

        assert len(published) == 0

    def test_continues_remaining_ports_after_exception(self, tmp_path: Path):
        call_count = 0

        class _CountProbe(ActiveProbe):
            probe_name = "_count_probe"
            default_ports = [80, 443, 8080]
            event_type = "_count_event"
            priority = 100

            def run(self, ip: str, port: int, timeout: float) -> dict[str, Any] | None:
                nonlocal call_count
                call_count += 1
                if port == 443:
                    raise OSError("refused")
                return None

            def syslog_fields(self, ip: str, port: int, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
                return {}, ""

            def publish_payload(self, ip: str, port: int, result: dict[str, Any]) -> dict[str, Any]:
                return {}

        probe = _CountProbe()
        ip_probed: dict[str, set[int]] = {}

        _run_probe(probe, "1.2.3.4", ip_probed, tmp_path / "a.log", tmp_path / "a.json",
                   timeout=1.0, publish_fn=None, record_rotation=None)

        assert call_count == 3  # all three ports attempted
        assert {80, 443, 8080} == ip_probed["_count_probe"]
