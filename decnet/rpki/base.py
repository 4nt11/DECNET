"""RPKI validator protocol.

Concrete validators (:mod:`decnet.rpki.ripestat`, future offline providers)
implement this. Callers must go through
:func:`~decnet.rpki.factory.get_validator`; never import a concrete
validator class directly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional

RpkiStatus = Literal["valid", "invalid", "not-found", "unknown"]


@dataclass(frozen=True)
class RpkiResult:
    """Outcome of a single RPKI validity check."""

    status: RpkiStatus
    prefix: Optional[str] = None  # announced prefix the validator resolved for this IP
    validated_at: Optional[datetime] = None


class Validator(ABC):
    """Abstract RPKI validator."""

    #: Short tag written to ``Attacker.rpki_source`` (e.g. ``'ripestat'``).
    name: str

    @abstractmethod
    def validate(self, ip: str, asn: int) -> RpkiResult:
        """Return RPKI validity for (ip, asn). Never raises."""

    def refresh(self) -> None:
        """No-op for online validators; offline providers may override."""
