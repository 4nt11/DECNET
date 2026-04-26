"""Driver protocol for orchestrator actions.

Future protocols (HTTP, SMB, MySQL, …) implement this interface alongside
the SSH driver. Kept deliberately minimal — the orchestrator only needs
"run this action and tell me how it went".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from decnet.orchestrator.scheduler import Action


@dataclass
class ActivityResult:
    """Outcome of one driver invocation.

    ``payload`` is the per-action JSON envelope the worker writes to the
    ``OrchestratorEvent.payload`` column and to the bus event body.
    """
    success: bool
    payload: dict[str, Any] = field(default_factory=dict)


class Driver(Protocol):
    async def run(self, action: Action) -> ActivityResult: ...
