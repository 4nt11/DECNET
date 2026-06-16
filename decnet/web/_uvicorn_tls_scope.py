# SPDX-License-Identifier: AGPL-3.0-or-later
"""Inject the TLS peer cert into ASGI scope — uvicorn ≤ 0.44 does not.

Uvicorn's h11/httptools HTTP protocols build the ASGI ``scope`` dict
without any ``extensions.tls`` entry, so per-request cert pinning
handlers (like POST /swarm/heartbeat) can't see the client cert that
CERT_REQUIRED already validated at handshake.

We patch ``RequestResponseCycle.__init__`` on both protocol modules to
read the peer cert off the asyncio transport (which *does* carry it)
and write the DER bytes into
``scope["extensions"]["tls"]["client_cert_chain"]``. This is the same
key the ASGI TLS extension proposal uses, so the application code will
keep working unchanged if a future uvicorn populates it natively.

Import this module once at app startup time (before uvicorn starts
accepting connections). Idempotent — subsequent imports are no-ops.
"""
from __future__ import annotations

from typing import Any


_PATCHED = False


def _wrap_cycle_init(cycle_cls) -> None:
    original = cycle_cls.__init__

    def _patched_init(self, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        transport = kwargs.get("transport") or getattr(self, "transport", None)
        if transport is None:
            return
        ssl_obj = transport.get_extra_info("ssl_object")
        if ssl_obj is None:
            return
        try:
            der = ssl_obj.getpeercert(binary_form=True)
        except Exception:
            return
        if not der:
            return
        # scope is a mutable dict uvicorn stores here; Starlette forwards
        # it to handlers as request.scope. Use setdefault so we don't clobber
        # any future native extension entries from uvicorn itself.
        scope = self.scope
        extensions = scope.setdefault("extensions", {})
        extensions.setdefault("tls", {"client_cert_chain": [der]})

    cycle_cls.__init__ = _patched_init


def install() -> None:
    """Patch uvicorn's HTTP cycle classes. Safe to call multiple times."""
    global _PATCHED
    if _PATCHED:
        return
    try:
        from uvicorn.protocols.http import h11_impl
        _wrap_cycle_init(h11_impl.RequestResponseCycle)
    except Exception:  # nosec B110 - optional uvicorn impl may be unavailable
        pass
    try:
        from uvicorn.protocols.http import httptools_impl
        _wrap_cycle_init(httptools_impl.RequestResponseCycle)
    except Exception:  # nosec B110 - optional uvicorn impl may be unavailable
        pass
    _PATCHED = True


# Auto-install on import so simply importing this module patches uvicorn.
install()
