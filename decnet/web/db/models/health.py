# SPDX-License-Identifier: AGPL-3.0-or-later
"""Health-endpoint DTOs."""
from typing import Literal, Optional

from pydantic import BaseModel


class ComponentHealth(BaseModel):
    status: Literal["ok", "failing"]
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    components: dict[str, ComponentHealth]
