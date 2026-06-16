# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bus emit helper for DeckyLifecycle transitions.

DB is the source of truth (wizard polls ``GET /deckies/lifecycle?ids=``).
The bus is best-effort live notification — publish failures are logged
and swallowed via ``publish_safely``, never propagated.
"""
from __future__ import annotations

from typing import Optional

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.publish import publish_safely


async def emit_lifecycle(
    bus: BaseBus | None,
    *,
    lifecycle_id: str,
    decky_name: str,
    operation: str,
    status: str,
    error: Optional[str] = None,
) -> None:
    """Publish ``decky.<name>.lifecycle`` with the current transition.

    Payload keys: ``lifecycle_id``, ``operation``, ``status`` and
    optionally ``error``.  Documented in
    ``wiki-checkout/Service-Bus.md``.
    """
    payload: dict = {
        "lifecycle_id": lifecycle_id,
        "operation": operation,
        "status": status,
    }
    if error is not None:
        payload["error"] = error
    await publish_safely(
        bus,
        _topics.decky_lifecycle(decky_name),
        payload,
        event_type=_topics.DECKY_LIFECYCLE,
    )
