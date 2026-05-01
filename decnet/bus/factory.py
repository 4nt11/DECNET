"""Bus factory — selects a :class:`~decnet.bus.base.BaseBus` implementation.

Dispatch key: the ``DECNET_BUS_TYPE`` environment variable.

* ``unix`` (default) → :class:`~decnet.bus.unix_client.UnixSocketBus`
* ``fake``           → :class:`~decnet.bus.fake.FakeBus` (in-process)

If ``DECNET_BUS_ENABLED`` is ``"false"`` the factory short-circuits to
:class:`~decnet.bus.fake.NullBus` regardless of ``DECNET_BUS_TYPE`` — a
cheap way for dev environments to run workers without a bus daemon.

Mirrors :mod:`decnet.web.db.factory` (lazy imports inside each branch,
env-driven dispatch, optional telemetry wrapping).  Callers MUST use
:func:`get_bus` rather than instantiating transports directly.
"""
from __future__ import annotations

import os
from typing import Any

from decnet.bus.base import BaseBus


def get_bus(**kwargs: Any) -> BaseBus:
    """Instantiate the bus implementation selected by environment.

    Keyword arguments are forwarded to the concrete transport:

    * ``UnixSocketBus`` accepts ``socket_path`` (overrides
      ``DECNET_BUS_SOCKET``) and ``client_name``.
    * ``FakeBus`` accepts ``queue_size``.
    """
    if os.environ.get("DECNET_BUS_ENABLED", "true").lower() == "false":
        from decnet.bus.fake import NullBus
        return NullBus()

    bus_type = os.environ.get("DECNET_BUS_TYPE", "unix").lower()

    if bus_type == "unix":
        from decnet.bus.unix_client import UnixSocketBus
        socket_path = kwargs.pop("socket_path", None) or _default_socket_path()
        bus: BaseBus = UnixSocketBus(socket_path=socket_path, **kwargs)
    elif bus_type == "fake":
        from decnet.bus.fake import FakeBus
        bus = FakeBus(**kwargs)
    else:
        raise ValueError(f"Unsupported bus type: {bus_type}")

    return _maybe_wrap_telemetry(bus)


def _default_socket_path() -> str:
    """Return the bus socket path honoring ``DECNET_BUS_SOCKET`` and falling
    back to ``/run/decnet/bus.sock`` → ``~/.decnet/bus.sock``.

    The runtime path (``/run/decnet``) is preferred because systemd
    ``RuntimeDirectory=decnet`` sets it up with the right perms; the home
    fallback keeps dev boxes usable without systemd.
    """
    explicit = os.environ.get("DECNET_BUS_SOCKET")
    if explicit:
        return explicit

    runtime_dir = "/run/decnet"
    if os.path.isdir(runtime_dir) and os.access(runtime_dir, os.W_OK):
        return f"{runtime_dir}/bus.sock"
    return os.path.expanduser("~/.decnet/bus.sock")


def _maybe_wrap_telemetry(bus: BaseBus) -> BaseBus:
    """Wrap *bus* in a tracing proxy if OTEL is enabled, else return as-is.

    Uses :func:`decnet.telemetry.wrap_repository` as the underlying proxy —
    its implementation is generic (wraps any async method in a span), so we
    reuse it with a bus-appropriate tracer name.  If telemetry isn't wired
    up at all we no-op.
    """
    try:
        from decnet.telemetry import wrap_repository
    except ImportError:
        return bus
    try:
        return wrap_repository(bus)
    except Exception:  # pragma: no cover - defensive
        return bus
