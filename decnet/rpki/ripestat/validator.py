"""RIPE STAT RPKI validator.

Resolves the most-specific announced prefix covering ``ip`` via the
RIPE STAT ``network-info`` endpoint, then validates ``(asn, prefix)``
via ``rpki-validation``. Results are cached in a SQLite database under
:data:`~decnet.rpki.paths.RPKI_ROOT` to avoid per-event network calls.

HTTP is wired in the next commit; this skeleton returns ``unknown``
unconditionally so the rest of the pipeline compiles and tests pass.
"""
from __future__ import annotations

from decnet.rpki.base import RpkiResult, Validator


class RipeStatValidator(Validator):
    name = "ripestat"

    def validate(self, ip: str, asn: int) -> RpkiResult:
        return RpkiResult(status="unknown")
