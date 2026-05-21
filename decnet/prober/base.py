"""
ActiveProbe ABC and metaclass registry for port-iterating active probes.

Adding a new active probe = one class with three methods.
IPv6 leak and TLS cert capture are NOT part of this registry (different
call shapes); they stay as special cases in prober/worker.py.
"""

from __future__ import annotations

import os
from abc import ABCMeta, abstractmethod
from typing import Any

from decnet.correlation.fingerprint_rotation import ProbeType


class ActiveProbeMeta(ABCMeta):
    """Metaclass that auto-registers every ActiveProbe subclass by probe_name."""

    _registry: dict[str, type[ActiveProbe]] = {}

    def __new__(
        mcs,
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, Any],
    ) -> ActiveProbeMeta:
        cls = super().__new__(mcs, name, bases, namespace)
        if bases and getattr(cls, "probe_name", None):
            mcs._registry[cls.probe_name] = cls  # type: ignore[attr-defined,assignment]
        return cls

    @classmethod
    def all(mcs) -> list[type[ActiveProbe]]:
        """Return registered probes sorted by (priority asc, probe_name asc)."""
        return sorted(mcs._registry.values(), key=lambda c: (c.priority, c.probe_name))


class ActiveProbe(metaclass=ActiveProbeMeta):
    """Base class for all port-iterating active probes.

    Subclasses declare class-level attributes and implement three methods.
    Registration is automatic via ActiveProbeMeta.

    Port override: set DECNET_PROBE_PORTS_<NAME_UPPER> (comma-separated) to
    override default_ports at runtime without touching the class.
    """

    probe_name: str
    default_ports: list[int | None]
    event_type: str
    rotation_type: ProbeType | None = None
    rotation_hash_key: str | None = None
    priority: int = 100

    def __init__(self) -> None:
        env_key = f"DECNET_PROBE_PORTS_{self.probe_name.upper()}"
        raw = os.environ.get(env_key, "").strip()
        if raw:
            try:
                self._ports: list[int | None] = [int(p.strip()) for p in raw.split(",") if p.strip()]
            except ValueError:
                self._ports = list(self.default_ports)
        else:
            self._ports = list(self.default_ports)

    @property
    def ports(self) -> list[int | None]:
        return self._ports

    @abstractmethod
    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        """Execute the probe against ip:port (port is None for port-free probes).

        Return a result dict on success, or None to suppress emission (e.g.
        empty JARM hash means the port doesn't speak TLS).
        """

    @abstractmethod
    def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Return (sd_fields, human_msg) for _write_event.

        target_ip and target_port are injected by _run_probe; do not include
        them in sd_fields.
        """

    @abstractmethod
    def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
        """Return the bus payload dict for attacker.fingerprinted events."""
