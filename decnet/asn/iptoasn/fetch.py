"""iptoasn.com bulk dump download.

One file: ``ip2asn-v4.tsv.gz``, ~5 MB compressed, refreshed daily.
Pulled over HTTPS with the same generic UA the geoip RIR fetcher uses
(stealth: never identify as DECNET — public-data scrapers correlated to
honeypot operator egress is the threat model).
"""
from __future__ import annotations

import logging
import shutil
import urllib.request
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("decnet.asn.iptoasn.fetch")

# Mirror the (name, url) tuple shape of geoip.rir.fetch so test
# harnesses can swap one for the other.
IPTOASN_SOURCES: Tuple[Tuple[str, str], ...] = (
    ("ip2asn-v4", "https://iptoasn.com/data/ip2asn-v4.tsv.gz"),
)

# Generic UA — matches geoip.rir.fetch. iptoasn.com explicitly releases
# the data into the public domain and does NOT require an identifying UA,
# so we keep DECNET stealth instead of advertising.
_USER_AGENT = "Mozilla/5.0 (compatible; fetch/1.0)"
_TIMEOUT_S = 60


def fetch_all(dest: Path) -> list[Path]:
    """Download every iptoasn file into *dest*. Returns the written paths.

    Atomic per file: download to ``{name}.tsv.gz.tmp`` then rename. A
    partial failure leaves the previous generation intact.
    """
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, url in IPTOASN_SOURCES:
        target = dest / f"{name}.tsv.gz"
        tmp = target.with_suffix(".gz.tmp")
        try:
            _download(url, tmp)
            tmp.replace(target)
            written.append(target)
            logger.info(
                "asn.iptoasn: fetched %s (%d bytes)",
                name, target.stat().st_size,
            )
        except Exception as exc:
            logger.error(
                "asn.iptoasn: fetch failed for %s (%s): %s", name, url, exc
            )
            if tmp.exists():
                tmp.unlink(missing_ok=True)
            # Keep any stale previous file — better outdated than empty.
    return written


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp, dest.open("wb") as fh:  # nosec B310 — fixed https iptoasn URL
        shutil.copyfileobj(resp, fh)
