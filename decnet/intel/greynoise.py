"""GreyNoise Community API provider.

Endpoint: ``GET https://api.greynoise.io/v3/community/<ip>``

The Community endpoint requires no API key for low-volume use; an
optional ``DECNET_GREYNOISE_API_KEY`` lifts the rate limit. We always
send the key when present.

Response shape (relevant fields)::

    {
      "ip": "1.2.3.4",
      "noise": true,             // observed scanning the public internet
      "riot": false,             // member of the "Rule It Out" benign set
      "classification": "benign | malicious | unknown",
      "name": "Censys",          // tool/operator label, when known
      "link": "https://...",
      "last_seen": "2026-04-25"
    }

Status code semantics:
* 200 — IP found, JSON body as above
* 404 — IP not observed by GreyNoise (treat as ``"unknown"``, not error)
* 429 — rate-limited (treat as transient error)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from decnet.intel.base import IntelProvider, IntelResult
from decnet.logging import get_logger
from decnet.net.http import stealth_client

log = get_logger("intel.greynoise")

_ENDPOINT = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseProvider(IntelProvider):
    name = "greynoise"
    concurrency = 4
    # Community tier is ~50/min; ~1.5s between dispatches keeps us well
    # under that without serialising entirely.
    min_dispatch_interval_s = 1.5

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__()
        self._api_key = api_key or os.environ.get(
            "DECNET_GREYNOISE_API_KEY"
        ) or None

    async def lookup(self, ip: str) -> IntelResult:
        url = _ENDPOINT.format(ip=ip)
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["key"] = self._api_key
        try:
            async with stealth_client() as client:
                resp = await client.get(url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            return IntelResult(provider=self.name, error=f"network: {exc}")

        if resp.status_code == 404:
            # IP not in GreyNoise's view of the internet — record the row
            # so we don't keep re-querying within the TTL window.
            return IntelResult(
                provider=self.name,
                verdict="unknown",
                column_updates={
                    "greynoise_classification": "unknown",
                    "greynoise_raw": json.dumps({"message": "not seen"}),
                    "greynoise_queried_at": datetime.now(timezone.utc),
                },
            )
        if resp.status_code != 200:
            return IntelResult(
                provider=self.name,
                error=f"HTTP {resp.status_code}",
            )

        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            return IntelResult(provider=self.name, error=f"parse: {exc}")

        classification = (data.get("classification") or "unknown").lower()
        verdict = _CLASSIFICATION_TO_VERDICT.get(classification, "unknown")
        return IntelResult(
            provider=self.name,
            verdict=verdict,
            column_updates={
                "greynoise_classification": classification,
                "greynoise_raw": json.dumps(data),
                "greynoise_queried_at": datetime.now(timezone.utc),
            },
        )


_CLASSIFICATION_TO_VERDICT = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "benign": "benign",
    "unknown": "unknown",
}
