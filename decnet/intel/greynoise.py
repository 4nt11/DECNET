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
                    "greynoise_name": None,
                    "greynoise_tags": [],
                    "greynoise_raw": {"message": "not seen"},
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
        # The Community endpoint surfaces an actor ``name`` (e.g. "Tor",
        # "Censys") but no behavioral tag list — the tag taxonomy is
        # paid-tier only. Persist whatever we got; a future non-Community
        # provider may populate ``greynoise_tags``.
        name_obj = data.get("name")
        name = name_obj if isinstance(name_obj, str) and name_obj else None
        tags_obj = data.get("tags")
        tags: list[str] = (
            [t for t in tags_obj if isinstance(t, str)]
            if isinstance(tags_obj, list) else []
        )
        return IntelResult(
            provider=self.name,
            verdict=verdict,
            column_updates={
                "greynoise_classification": classification,
                "greynoise_name": name,
                "greynoise_tags": tags,
                "greynoise_raw": data,
                "greynoise_queried_at": datetime.now(timezone.utc),
            },
        )


_CLASSIFICATION_TO_VERDICT = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "benign": "benign",
    "unknown": "unknown",
}
