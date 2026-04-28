"""abuse.ch ThreatFox provider — per-IOC query API.

Endpoint: ``POST https://threatfox-api.abuse.ch/api/v1/``

ThreatFox returns IOC matches across many types (URL, domain, IP, hash).
We send ``{"query": "search_ioc", "search_term": "<ip>"}`` and treat any
non-empty ``data`` array as a malicious match.

API key handling: ThreatFox accepts an optional ``Auth-Key`` header for
higher rate limits. Without a key the public endpoint still answers but
caps requests/min — the provider works either way.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from decnet.intel.base import IntelProvider, IntelResult
from decnet.logging import get_logger
from decnet.net.http import stealth_client

log = get_logger("intel.threatfox")

_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(IntelProvider):
    name = "threatfox"
    concurrency = 4
    min_dispatch_interval_s = 0.5

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__()
        self._api_key = api_key or os.environ.get(
            "DECNET_THREATFOX_API_KEY"
        ) or None

    async def lookup(self, ip: str) -> IntelResult:
        body = {"query": "search_ioc", "search_term": ip}
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Auth-Key"] = self._api_key

        try:
            async with stealth_client() as client:
                resp = await client.post(
                    _ENDPOINT, headers=headers, json=body,
                )
        except Exception as exc:  # noqa: BLE001
            return IntelResult(provider=self.name, error=f"network: {exc}")

        if resp.status_code != 200:
            return IntelResult(
                provider=self.name, error=f"HTTP {resp.status_code}",
            )
        try:
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            return IntelResult(provider=self.name, error=f"parse: {exc}")

        status = payload.get("query_status")
        # ThreatFox returns query_status="no_result" when the IOC isn't
        # tracked, and query_status="ok" with a non-empty data list when
        # it is. Anything else (illegal_search, etc.) is a contract
        # violation we surface as an error.
        if status == "no_result":
            return IntelResult(
                provider=self.name,
                verdict=None,  # absence is not a benign signal
                column_updates={
                    "threatfox_listed": False,
                    "threatfox_raw": "{}",
                    "threatfox_queried_at": datetime.now(timezone.utc),
                },
            )
        if status != "ok":
            return IntelResult(
                provider=self.name,
                error=f"query_status={status!r}",
            )

        data = payload.get("data") or []
        listed = bool(data)
        return IntelResult(
            provider=self.name,
            verdict="malicious" if listed else None,
            column_updates={
                "threatfox_listed": listed,
                "threatfox_raw": json.dumps(data),
                "threatfox_queried_at": datetime.now(timezone.utc),
            },
        )
