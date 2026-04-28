"""DECNET ServiceBus — pub/sub notification substrate.

The bus is the notification layer for DECNET's worker constellation.  The DB
remains the source of truth for anything durable; the bus carries "something
happened, go look" events.  Delivery is at-most-once, fire-and-forget.

Consumers call :func:`get_bus` from :mod:`decnet.bus.factory`; never import
transport implementations directly.  The factory selects the backend via
``DECNET_BUS_TYPE`` (``nats`` or ``fake``) and honors ``DECNET_BUS_ENABLED``.

Topic hierarchy is defined in :mod:`decnet.bus.topics` and locked early so
consumers can subscribe with stable wildcard patterns.
"""
from __future__ import annotations

from decnet.bus.base import BaseBus, Event, Subscription

__all__ = ["BaseBus", "Event", "Subscription"]
