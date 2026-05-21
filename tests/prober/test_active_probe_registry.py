"""Tests for ActiveProbeMeta registry and ActiveProbe ABC contract."""

from __future__ import annotations

from typing import Any

import pytest

from decnet.prober.base import ActiveProbe, ActiveProbeMeta
import decnet.prober.probes as _probes  # noqa: F401 — ensure probes are registered


@pytest.fixture(autouse=True)
def _restore_registry():
    """Snapshot and restore the registry around each test so throwaway probes don't leak."""
    snapshot = dict(ActiveProbeMeta._registry)
    yield
    ActiveProbeMeta._registry.clear()
    ActiveProbeMeta._registry.update(snapshot)


class TestRegistryContents:

    def test_all_probes_registered(self):
        names = {cls.probe_name for cls in ActiveProbeMeta.all()}
        assert names == {"jarm", "hassh", "tcpfp", "ipv6_leak", "tls_certificate", "icmp_error"}

    def test_sorted_by_priority_then_name(self):
        order = [cls.probe_name for cls in ActiveProbeMeta.all()]
        # priority=100: hassh/jarm/tcpfp (alphabetical)
        # priority=200: tls_certificate
        # priority=850: icmp_error
        # priority=999: ipv6_leak
        assert order == ["hassh", "jarm", "tcpfp", "tls_certificate", "icmp_error", "ipv6_leak"]

    def test_priority10_probe_sorts_first(self):
        class _FastProbe(ActiveProbe):
            probe_name = "_fast_test_probe"
            default_ports: list[int | None] = [9999]
            event_type = "_fast_event"
            priority = 10

            def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
                return None

            def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
                return {}, ""

            def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
                return {}

        order = [cls.probe_name for cls in ActiveProbeMeta.all()]
        assert order[0] == "_fast_test_probe"
        assert set(order[1:]) == {"hassh", "jarm", "tcpfp", "ipv6_leak", "tls_certificate", "icmp_error"}

    def test_port_none_probe_dispatched_with_none_port(self):
        """_run_probe must call run(ip, None, timeout) for a port-free probe."""
        calls: list[tuple] = []

        class _NullPortProbe(ActiveProbe):
            probe_name = "_null_port_test"
            default_ports: list[int | None] = [None]
            event_type = "_null_event"
            priority = 10

            def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
                calls.append((ip, port))
                return None

            def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
                return {}, ""

            def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
                return {}

        from pathlib import Path
        from decnet.prober.worker import _run_probe

        _run_probe(
            _NullPortProbe(), "10.0.0.1", {},
            Path("/dev/null"), Path("/dev/null"),
            timeout=1.0, publish_fn=None, record_rotation=None,
        )
        assert calls == [("10.0.0.1", None)]

    def test_base_class_not_registered(self):
        assert "ActiveProbe" not in ActiveProbeMeta._registry
        assert None not in ActiveProbeMeta._registry.values()


class TestProbeABCContract:

    @pytest.mark.parametrize("probe_cls", list(ActiveProbeMeta.all()))
    def test_instantiable(self, probe_cls: type[ActiveProbe]):
        instance = probe_cls()
        assert isinstance(instance, ActiveProbe)

    @pytest.mark.parametrize("probe_cls", list(ActiveProbeMeta.all()))
    def test_has_required_class_attrs(self, probe_cls: type[ActiveProbe]):
        assert isinstance(probe_cls.probe_name, str) and probe_cls.probe_name
        assert isinstance(probe_cls.default_ports, list) and probe_cls.default_ports
        assert isinstance(probe_cls.event_type, str) and probe_cls.event_type
        assert isinstance(probe_cls.priority, int)

    @pytest.mark.parametrize("probe_cls", list(ActiveProbeMeta.all()))
    def test_ports_property_reflects_default(self, probe_cls: type[ActiveProbe]):
        instance = probe_cls()
        assert instance.ports == probe_cls.default_ports

    @pytest.mark.parametrize("probe_cls", list(ActiveProbeMeta.all()))
    def test_implements_abstract_methods(self, probe_cls: type[ActiveProbe]):
        assert callable(getattr(probe_cls, "run"))
        assert callable(getattr(probe_cls, "syslog_fields"))
        assert callable(getattr(probe_cls, "publish_payload"))
