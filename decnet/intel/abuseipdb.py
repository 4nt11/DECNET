"""AbuseIPDB provider.

Endpoint: ``GET https://api.abuseipdb.com/api/v2/check``

Free tier: 1000 lookups/day. Always requires an API key passed in the
``Key`` header — the provider self-disables (returns an error) when no
key is configured rather than burning quota at the free public IP.

Verdict mapping is tier-based on the ``abuseConfidenceScore`` (0–100):

* ``>= 75`` — ``malicious``
* ``25..74`` — ``suspicious``
* ``< 25``  — ``benign``

This matches AbuseIPDB's own UI thresholds reasonably closely; tune
later if operators report drift.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from decnet.intel.base import IntelProvider, IntelResult
from decnet.logging import get_logger
from decnet.net.http import stealth_client

log = get_logger("intel.abuseipdb")

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
_DEFAULT_MAX_AGE_DAYS = 30


def _score_to_verdict(score: int) -> str:
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "benign"


class AbuseIPDBProvider(IntelProvider):
    name = "abuseipdb"
    concurrency = 4
    # 1000/day = avg 1 every ~86s. We don't enforce the daily cap here —
    # operators who burn it through the worker will see HTTP 429 and the
    # row gets retried after the TTL window.
    min_dispatch_interval_s = 0.5

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
    ) -> None:
        super().__init__()
        self._api_key = api_key or os.environ.get(
            "DECNET_ABUSEIPDB_API_KEY"
        ) or None
        self._max_age_days = max_age_days

    async def lookup(self, ip: str) -> IntelResult:
        if not self._api_key:
            return IntelResult(
                provider=self.name,
                error="DECNET_ABUSEIPDB_API_KEY not configured",
            )
        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(self._max_age_days),
        }
        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
        }
        try:
            async with stealth_client() as client:
                resp = await client.get(_ENDPOINT, headers=headers, params=params)
        except Exception as exc:  # noqa: BLE001
            return IntelResult(provider=self.name, error=f"network: {exc}")

        if resp.status_code != 200:
            return IntelResult(
                provider=self.name,
                error=f"HTTP {resp.status_code}",
            )
        try:
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            return IntelResult(provider=self.name, error=f"parse: {exc}")

        data = payload.get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        verdict = _score_to_verdict(score)
        # AbuseIPDB returns ``data.reports[*].categories`` — a list of
        # int codes per report. Flatten the union across all recent
        # reports so the IntelLifter sees the full activity profile,
        # not just the most-recent report's categories. Sorted for
        # determinism (matters for tests + for the bus payload diff).
        categories: set[int] = set()
        for report in data.get("reports") or []:
            if not isinstance(report, dict):
                continue
            for cat in report.get("categories") or []:
                if isinstance(cat, int):
                    categories.add(cat)
        return IntelResult(
            provider=self.name,
            verdict=verdict,
            column_updates={
                "abuseipdb_score": score,
                "abuseipdb_categories": json.dumps(sorted(categories)),
                "abuseipdb_raw": json.dumps(data),
                "abuseipdb_queried_at": datetime.now(timezone.utc),
            },
        )
