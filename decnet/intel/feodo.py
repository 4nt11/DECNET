# SPDX-License-Identifier: AGPL-3.0-or-later
"""abuse.ch Feodo Tracker provider — bulk JSON botnet C2 feed.

Endpoint: ``GET https://feodotracker.abuse.ch/downloads/ipblocklist.json``

This is the only provider in the v1 set that uses a *bulk* feed instead
of a per-IP query: the upstream is a list of every botnet C2 IP abuse.ch
has seen recently (Emotet, TrickBot, Dridex, etc.), refreshed every few
minutes. We fetch the full list once per ``refresh_interval_s`` and
answer ``lookup(ip)`` calls from the in-process set.

This makes Feodo Tracker effectively free at the call-site: thousands
of attacker IPs map to a single network round-trip per refresh window.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional

from decnet.intel.base import IntelProvider, IntelResult
from decnet.logging import get_logger
from decnet.net.http import stealth_client

log = get_logger("intel.feodo")

_ENDPOINT = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_DEFAULT_REFRESH_S = 3600.0


class FeodoProvider(IntelProvider):
    name = "feodo"
    concurrency = 1  # only one concurrent refresh; lookups are pure set ops
    min_dispatch_interval_s = 0.0

    def __init__(self, *, refresh_interval_s: float = _DEFAULT_REFRESH_S) -> None:
        super().__init__()
        self._refresh_interval_s = refresh_interval_s
        # ip → upstream record dict, keyed by ``ip_address``.
        self._index: dict[str, dict[str, Any]] = {}
        self._loaded_at: float = 0.0
        self._last_error: Optional[str] = None

    async def _refresh(self) -> Optional[str]:
        """Refetch the bulk feed. Returns an error string or ``None``."""
        try:
            async with stealth_client(timeout=20.0) as client:
                resp = await client.get(_ENDPOINT)
        except Exception as exc:  # noqa: BLE001
            return f"network: {exc}"
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        try:
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            return f"parse: {exc}"
        if not isinstance(payload, list):
            return "feed: not a list"

        new_index: dict[str, dict[str, Any]] = {}
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip_address")
            if isinstance(ip, str):
                new_index[ip] = entry
        self._index = new_index
        self._loaded_at = time.monotonic()
        self._last_error = None
        log.info("feodo: refreshed bulk feed entries=%d", len(new_index))
        return None

    async def _ensure_fresh(self) -> None:
        if (
            not self._index
            or (time.monotonic() - self._loaded_at) >= self._refresh_interval_s
        ):
            err = await self._refresh()
            if err:
                self._last_error = err

    async def lookup(self, ip: str) -> IntelResult:
        await self._ensure_fresh()
        if not self._index and self._last_error:
            return IntelResult(provider=self.name, error=self._last_error)

        entry = self._index.get(ip)
        if entry is None:
            # Not on the C2 list — explicit benign-ish signal. Cache it
            # so we don't keep checking the same set on every wake.
            return IntelResult(
                provider=self.name,
                verdict=None,  # absence ≠ "benign", let other providers speak
                column_updates={
                    "feodo_listed": False,
                    "feodo_malware_family": None,
                    "feodo_raw": {},
                    "feodo_queried_at": datetime.now(timezone.utc),
                },
            )
        family_obj = entry.get("malware")
        family = (
            family_obj if isinstance(family_obj, str) and family_obj else None
        )
        return IntelResult(
            provider=self.name,
            verdict="malicious",
            column_updates={
                "feodo_listed": True,
                "feodo_malware_family": family,
                "feodo_raw": entry,
                "feodo_queried_at": datetime.now(timezone.utc),
            },
        )
