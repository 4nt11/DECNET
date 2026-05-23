# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for :func:`decnet.bus.factory.get_bus` dispatch."""
from __future__ import annotations

import pathlib

import pytest

from decnet.bus.factory import _default_socket_path, get_bus
from decnet.bus.fake import FakeBus, NullBus
from decnet.bus.unix_client import UnixSocketBus


def test_disabled_returns_null_bus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    monkeypatch.setenv("DECNET_BUS_TYPE", "unix")  # ignored when disabled
    bus = get_bus()
    assert isinstance(bus, NullBus)


def test_fake_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_BUS_ENABLED", "true")
    monkeypatch.setenv("DECNET_BUS_TYPE", "fake")
    bus = get_bus()
    assert isinstance(bus, FakeBus)


def test_unix_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    monkeypatch.setenv("DECNET_BUS_ENABLED", "true")
    monkeypatch.setenv("DECNET_BUS_TYPE", "unix")
    monkeypatch.setenv("DECNET_BUS_SOCKET", str(tmp_path / "b.sock"))
    bus = get_bus()
    assert isinstance(bus, UnixSocketBus)


def test_unknown_type_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_BUS_ENABLED", "true")
    monkeypatch.setenv("DECNET_BUS_TYPE", "mqtt")
    with pytest.raises(ValueError, match="Unsupported bus type"):
        get_bus()


def test_default_socket_path_honors_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_BUS_SOCKET", "/tmp/explicit.sock")
    assert _default_socket_path() == "/tmp/explicit.sock"


def test_default_socket_path_falls_back_to_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DECNET_BUS_SOCKET", raising=False)
    # Force /run/decnet to look unusable.
    monkeypatch.setattr("os.path.isdir", lambda p: False)
    path = _default_socket_path()
    assert path.endswith(".decnet/bus.sock")
