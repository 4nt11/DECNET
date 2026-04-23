"""Workers panel DTOs (bus-backed health + control)."""
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field as PydanticField


# --- Workers panel (Config → Workers) ---
# Bus-backed health + control: workers heartbeat on ``system.<name>.health``
# and listen on ``system.<name>.control``.  The API aggregates last-seen
# heartbeats via the worker registry; these are the HTTP-facing shapes.

class WorkerStatus(BaseModel):
    name: str
    # ``ok`` — heartbeat within 90s (3× 30s heartbeat interval)
    # ``stale`` — worker was seen before but hasn't pulsed in 90s+
    # ``unknown`` — we've never received a heartbeat from this name
    status: Literal["ok", "stale", "unknown"]
    last_heartbeat_ts: Optional[float] = None
    seconds_since: Optional[float] = None
    # Whatever the worker's ``extra()`` callback put in the heartbeat;
    # opaque to the panel, displayed only if the UI knows the key.
    extra: Dict[str, Any] = PydanticField(default_factory=dict)
    # True iff a ``decnet-<name>.service`` unit file is present on the
    # host.  False flips the UI START button to disabled with a
    # "Unit not installed" tooltip.  Default True for backwards compat
    # on clients that pre-date the field.
    installed: bool = True


class WorkersResponse(BaseModel):
    workers: List[WorkerStatus]
    generated_at: float
    bus_connected: bool


class WorkerControlResponse(BaseModel):
    accepted: bool
    worker: str
    action: str


class StartFailure(BaseModel):
    name: str
    reason: str


class StartAllResponse(BaseModel):
    started: List[str]
    already_running: List[str]
    failed: List[StartFailure]
