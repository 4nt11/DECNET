"""RIPE STAT RPKI validator.

Resolves the most-specific announced prefix covering ``ip`` via the
RIPE STAT ``network-info`` endpoint, then validates ``(asn, prefix)``
via ``rpki-validation``. Results are cached in a SQLite database under
:data:`~decnet.rpki.paths.RPKI_ROOT`.

Two HTTP calls per uncached IP (``network-info`` + ``rpki-validation``),
each with a 2-second timeout. Any network failure collapses to
``status="unknown"`` — the caller upserts the attacker row regardless.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from decnet.rpki import cache as _cache
from decnet.rpki.base import RpkiResult, RpkiStatus, Validator
from decnet.rpki.paths import ensure_root

logger = logging.getLogger("decnet.rpki.ripestat")

_TIMEOUT_S = 2
_STAT_BASE = "https://stat.ripe.net/data"
_UA = "Mozilla/5.0 (compatible; fetch/1.0)"


class RipeStatValidator(Validator):
    name = "ripestat"

    def __init__(self) -> None:
        db_path = ensure_root() / "cache.db"
        self._con: sqlite3.Connection = _cache.open_db(db_path)
        _cache.prune(self._con)

    def validate(self, ip: str, asn: int) -> RpkiResult:
        cached = _cache.get(self._con, ip)
        if cached is not None:
            status, prefix = cached
            return RpkiResult(status=status, prefix=prefix)  # type: ignore[arg-type]

        try:
            prefix = self._network_info(ip)
            if prefix is None:
                return self._store(ip, asn, "not-found", None)
            status = self._rpki_validation(asn, prefix)
            return self._store(ip, asn, status, prefix)
        except Exception as exc:
            logger.debug("rpki.ripestat: lookup failed for %s / AS%s: %s", ip, asn, exc)
            return RpkiResult(status="unknown")

    # ---------- internal ----------

    def _network_info(self, ip: str) -> Optional[str]:
        """Return the most-specific announced prefix containing *ip*, or None."""
        data = self._fetch(f"{_STAT_BASE}/network-info/data.json?resource={ip}")
        return data.get("data", {}).get("prefix") or None

    def _rpki_validation(self, asn: int, prefix: str) -> RpkiStatus:
        """Return RPKI state for (asn, prefix)."""
        data = self._fetch(
            f"{_STAT_BASE}/rpki-validation/data.json?resource={asn}&prefix={prefix}"
        )
        raw = data.get("data", {}).get("status", "unknown")
        if raw in ("valid", "invalid", "not-found"):
            return raw
        return "unknown"

    def _fetch(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # nosec B310 — HTTPS RIPE STAT base URL only; IP/ASN components are validated upstream
            return json.loads(resp.read())

    def _store(
        self, ip: str, asn: int, status: str, prefix: Optional[str]
    ) -> RpkiResult:
        try:
            _cache.put(self._con, ip, asn, status, prefix)
        except Exception as exc:
            logger.debug("rpki.ripestat: cache write failed: %s", exc)
        return RpkiResult(
            status=status,  # type: ignore[arg-type]
            prefix=prefix,
            validated_at=datetime.now(timezone.utc),
        )
