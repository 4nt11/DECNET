"""DB-row + bus-topic helpers for the orchestrator."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from decnet.bus import topics as _topics
from decnet.orchestrator.drivers.base import ActivityResult
from decnet.orchestrator.scheduler import (
    Action,
    EditAction,
    FileAction,
    TrafficAction,
)


def to_row(action: Action, result: ActivityResult) -> dict[str, Any]:
    """Build the kwargs dict for ``OrchestratorEvent(**...)``."""
    base: dict[str, Any] = {
        "ts": datetime.now(timezone.utc),
        "protocol": "ssh",
        "success": result.success,
        "payload": result.payload,  # repo serialises dict→json
    }
    if isinstance(action, TrafficAction):
        base.update(
            kind="traffic",
            action=f"exec:{action.description}",
            src_decky_uuid=action.src_uuid,
            dst_decky_uuid=action.dst_uuid,
        )
    elif isinstance(action, FileAction):
        base.update(
            kind="file",
            action=action.description,
            src_decky_uuid=None,
            dst_decky_uuid=action.dst_uuid,
        )
    elif isinstance(action, EditAction):
        # EditAction shares the "file" kind (same dashboard view, same
        # bus topic family) but action="file:edit" lets queries
        # discriminate when needed.
        base.update(
            kind="file",
            action=action.description,
            src_decky_uuid=None,
            dst_decky_uuid=action.dst_uuid,
        )
    else:
        raise TypeError(f"unsupported action type: {type(action)!r}")
    return base


def topic_for(action: Action) -> str:
    """Map an action to its bus topic."""
    if isinstance(action, TrafficAction):
        return _topics.orchestrator(_topics.ORCHESTRATOR_TRAFFIC, action.dst_uuid)
    if isinstance(action, (FileAction, EditAction)):
        return _topics.orchestrator(_topics.ORCHESTRATOR_FILE, action.dst_uuid)
    raise TypeError(f"unsupported action type: {type(action)!r}")


def event_type_for(action: Action) -> str:
    if isinstance(action, TrafficAction):
        return _topics.ORCHESTRATOR_TRAFFIC
    if isinstance(action, (FileAction, EditAction)):
        return _topics.ORCHESTRATOR_FILE
    raise TypeError(f"unsupported action type: {type(action)!r}")
