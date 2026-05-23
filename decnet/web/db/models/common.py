# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generic response shapes used across multiple router domains."""
from __future__ import annotations

from pydantic import BaseModel


class MessageResponse(BaseModel):
    """Standard envelope for mutations whose only payload is a status message.

    Pinning the wire shape at the decorator (``response_model=MessageResponse``)
    prevents a handler that accidentally returns a richer dict — e.g. a user
    row with ``password_hash`` — from leaking extra fields to the client.
    """

    message: str
