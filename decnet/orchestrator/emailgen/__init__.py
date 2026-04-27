"""Emailgen — second orchestrator worker.

Generates fake corporate emails (multi-language, threaded, persona-driven)
and drops them into mail-decky maildirs so attackers landing on
IMAP/POP3 honeypots find believable mailboxes instead of empty inboxes.

The module is intentionally a sibling of :mod:`decnet.orchestrator` (not
a flag on it) — separate worker, separate CLI command
(``decnet emailgen``), separate systemd-supervised lifecycle. Shares the
heartbeat / control-listener scaffolding via :mod:`decnet.bus.publish`.

Lazy worker re-export: :func:`emailgen_worker` is loaded on first
attribute access so that submodules can import package-level names
(``decnet.orchestrator.emailgen.events``) without triggering an eager
load of the worker — and through it, the email driver, which imports
back into this package.  Without lazy loading the package + driver +
worker form a cycle.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from decnet.orchestrator.emailgen.worker import emailgen_worker  # noqa: F401

__all__ = ["emailgen_worker"]


def __getattr__(name: str) -> Any:
    if name == "emailgen_worker":
        from decnet.orchestrator.emailgen.worker import emailgen_worker as _w
        return _w
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
