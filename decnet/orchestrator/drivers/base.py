"""Driver ABC for orchestrator actions.

Each concrete driver (SSH, Email, future HTTP/SMB/MySQL) maps one
:class:`~decnet.orchestrator.scheduler.Action` shape to a side effect
on a target decky and returns an :class:`ActivityResult` the
orchestrator persists.

The ABC lives here, the dispatch factory in
:mod:`decnet.orchestrator.drivers` ``__init__``, and the impls in
sibling modules — same pattern as :mod:`decnet.canary.factory`,
:mod:`decnet.web.db.factory`, and :mod:`decnet.bus.factory`.

Why ABC and not :class:`Protocol`: drivers also expose lower-level
helpers (``plant_file``, ``read_file``) that the planner-driven
realism path will call directly without going through ``run``.
Inheritance pins the contract for those helpers; a structural
protocol would let a typo silently produce a half-implemented driver.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from decnet.orchestrator.scheduler import Action


@dataclass
class ActivityResult:
    """Outcome of one driver invocation.

    ``payload`` is the per-action JSON envelope the worker writes to
    the ``OrchestratorEvent.payload`` column and to the bus event
    body.
    """
    success: bool
    payload: dict[str, Any] = field(default_factory=dict)


class ActivityDriver(ABC):
    """Base class every concrete orchestrator driver inherits.

    Subclasses MUST implement :meth:`run` — the action-shape dispatch.
    Subclasses that interact with files on the target decky SHOULD
    implement :meth:`plant_file` and :meth:`read_file` so the realism
    edit-in-place path can read existing artifacts before mutating
    them.  Drivers that don't touch files (e.g. a future pure-traffic
    driver) raise :class:`NotImplementedError` from those, and the
    planner avoids picking ``EditAction`` for them.
    """

    @abstractmethod
    async def run(self, action: Action) -> ActivityResult:
        """Execute the action against its target decky."""

    async def plant_file(
        self,
        decky_name: str,
        path: str,
        content: bytes,
        *,
        mode: int = 0o600,
        mtime: datetime | None = None,
    ) -> ActivityResult:
        """Write *content* to *path* inside *decky_name*.

        Default raises :class:`NotImplementedError`; concrete drivers
        that have a write transport (docker exec, ssh, etc.) override.
        Bytes-typed so binary artifacts (DOCX/PDF) survive the wire.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support plant_file"
        )

    async def read_file(self, decky_name: str, path: str) -> bytes:
        """Read *path* from inside *decky_name*.

        Required for the realism edit-in-place flow (stage 3b of the
        realism migration): the driver reads the previous body, the
        realism engine produces the next iteration, the driver writes
        it back.  Default raises :class:`NotImplementedError`.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support read_file"
        )


# Back-compat alias so existing imports of ``Driver`` keep working
# while consumers transition to ``ActivityDriver``.  Removed once the
# realism migration is complete.
Driver = ActivityDriver
