"""Fleet deploy + mutate-interval request DTOs."""
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field as PydanticField

from decnet.models import IniContent


class MutateIntervalRequest(BaseModel):
    # Human-readable duration: <number><unit> where unit is m(inutes), d(ays), M(onths), y/Y(ears).
    # Minimum granularity is 1 minute. Seconds are not accepted.
    mutate_interval: Optional[str] = PydanticField(None, pattern=r"^[1-9]\d*[mdMyY]$")


class DeployIniRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # This field now enforces strict INI structure during Pydantic initialization.
    # The OpenAPI schema correctly shows it as a required string.
    ini_content: IniContent = PydanticField(..., description="A valid INI formatted string")


class DeployResponse(BaseModel):
    """202-Accepted response: deploy spawned in background, client polls
    GET /deckies/lifecycle?ids=... until each row reaches a terminal
    status."""
    message: str
    mode: str
    lifecycle_ids: list[str] = PydanticField(default_factory=list)


class PurgeResponse(BaseModel):
    message: str
    deleted: dict[str, int]
