"""Regression tests for the uvicorn TLS scope monkey-patch."""
from __future__ import annotations

from typing import Any

import pytest


class _FakeSSLObject:
    def __init__(self, der: bytes) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return self._der


class _FakeTransport:
    def __init__(self, ssl_obj: Any = None) -> None:
        self._ssl = ssl_obj

    def get_extra_info(self, key: str) -> Any:
        if key == "ssl_object":
            return self._ssl
        return None


def _make_cycle_cls():
    class Cycle:
        def __init__(self, scope: dict, transport: Any = None) -> None:
            self.scope = scope
            self.transport = transport
    return Cycle


def test_wrap_cycle_injects_cert_into_scope() -> None:
    from decnet.web._uvicorn_tls_scope import _wrap_cycle_init

    Cycle = _make_cycle_cls()
    _wrap_cycle_init(Cycle)

    scope: dict = {"type": "http"}
    transport = _FakeTransport(_FakeSSLObject(b"\x30\x82der"))
    Cycle(scope, transport=transport)

    assert scope["extensions"]["tls"]["client_cert_chain"] == [b"\x30\x82der"]


def test_wrap_cycle_noop_when_no_ssl() -> None:
    from decnet.web._uvicorn_tls_scope import _wrap_cycle_init

    Cycle = _make_cycle_cls()
    _wrap_cycle_init(Cycle)

    scope: dict = {"type": "http"}
    Cycle(scope, transport=_FakeTransport(ssl_obj=None))

    assert "extensions" not in scope or "tls" not in scope.get("extensions", {})


def test_wrap_cycle_noop_when_empty_der() -> None:
    from decnet.web._uvicorn_tls_scope import _wrap_cycle_init

    Cycle = _make_cycle_cls()
    _wrap_cycle_init(Cycle)

    scope: dict = {"type": "http"}
    Cycle(scope, transport=_FakeTransport(_FakeSSLObject(b"")))

    assert "extensions" not in scope or "tls" not in scope.get("extensions", {})


def test_install_is_idempotent() -> None:
    from decnet.web import _uvicorn_tls_scope as mod

    mod.install()
    mod.install()  # second call must not double-wrap
