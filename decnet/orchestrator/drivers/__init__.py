# SPDX-License-Identifier: AGPL-3.0-or-later
"""Activity drivers for the orchestrator.

Concrete drivers register dispatch in :func:`get_driver_for`.  Same
lazy-import pattern as :mod:`decnet.canary.factory`: the import-time
cost of :mod:`decnet.orchestrator.drivers` stays low for callers that
only need :class:`ActivityResult` / :class:`ActivityDriver`.
"""
from __future__ import annotations

from decnet.orchestrator.drivers.base import (
    ActivityDriver,
    ActivityResult,
    Driver,
)
from decnet.orchestrator.scheduler import Action, EditAction, FileAction, TrafficAction

__all__ = [
    "ActivityDriver",
    "ActivityResult",
    "Driver",
    "SSHDriver",
    "get_driver_for",
]


def __getattr__(name: str):  # pragma: no cover - import passthrough
    """Lazy access to concrete drivers.

    Avoids dragging the docker-exec / email-driver code into every
    consumer that only needs the ABC.
    """
    if name == "SSHDriver":
        from decnet.orchestrator.drivers.ssh import SSHDriver
        return SSHDriver
    if name == "EmailDriver":
        from decnet.orchestrator.drivers.email import EmailDriver
        return EmailDriver
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_driver_for(action: Action) -> ActivityDriver:
    """Return the concrete driver that handles *action*.

    Stage 4 of the realism migration adds this seam so the orchestrator
    worker can dispatch by action type without an isinstance chain in
    ``_one_tick``.  Stage 5 wires the worker to call this function
    instead of holding a single ``SSHDriver`` instance.

    The set of action shapes the orchestrator can plan grows with the
    migration:

    * :class:`TrafficAction` / :class:`FileAction` → :class:`SSHDriver`
    * :class:`EmailAction` (post-stage-5) → ``EmailDriver``
    * :class:`EditAction` (post-stage-3b) → :class:`SSHDriver`
    """
    # Lazy imports keep the side-effecting docker-exec / email-driver
    # modules out of every importer's graph.
    from decnet.orchestrator.drivers.ssh import SSHDriver

    if isinstance(action, (TrafficAction, FileAction, EditAction)):
        return SSHDriver()
    # EmailAction lands in stage 5; reachable only after that import is
    # added to scheduler.  Importing inside the branch avoids a cycle
    # with realism.llm at module load time.
    try:
        from decnet.orchestrator.emailgen.scheduler import EmailAction
    except ImportError:  # pragma: no cover - scheduler always exists
        EmailAction = None  # type: ignore[misc]
    if EmailAction is not None and isinstance(action, EmailAction):
        from decnet.orchestrator.drivers.email import EmailDriver
        return EmailDriver()
    raise TypeError(
        f"no driver registered for action type {type(action).__name__}"
    )
