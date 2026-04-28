"""RIR delegated-stats download.

Five public files, ~5 MB total. Pulled over HTTPS with a generic
User-Agent (stealth: never identify as DECNET — a RIR log scraper could
otherwise correlate our egress to a honeypot operator).
"""
from __future__ import annotations

import logging
import shutil
import urllib.request
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("decnet.geoip.rir.fetch")

# (registry_name, url). Extended delegated-stats include the opaque
# registration ID we don't use, but they are what the RIRs recommend
# consumers pull.
RIR_SOURCES: Tuple[Tuple[str, str], ...] = (
    ("arin",    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
    ("ripe",    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"),
    ("apnic",   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
    ("lacnic",  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
    ("afrinic", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"),
)

# Generic UA — no DECNET/honeypot token. Matches what a stock requests/
# urllib script would send if someone forgot to set one.
_USER_AGENT = "Mozilla/5.0 (compatible; fetch/1.0)"
_TIMEOUT_S = 60


def fetch_all(dest: Path) -> list[Path]:
    """Download every RIR file into *dest*. Returns the written paths.

    Atomic per file: we download to ``{name}.txt.tmp`` then rename. A
    partial failure leaves the previous generation intact.
    """
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, url in RIR_SOURCES:
        target = dest / f"{name}.txt"
        tmp = target.with_suffix(".txt.tmp")
        try:
            _download(url, tmp)
            tmp.replace(target)
            written.append(target)
            logger.info("geoip.rir: fetched %s (%d bytes)", name, target.stat().st_size)
        except Exception as exc:
            logger.error("geoip.rir: fetch failed for %s (%s): %s", name, url, exc)
            if tmp.exists():
                tmp.unlink(missing_ok=True)
            # Keep any stale previous file — better outdated than empty.
    return written


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    # `with` closes the response + dest file on any path.
    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp, dest.open("wb") as fh:  # nosec B310 — fixed https RIR URLs
        shutil.copyfileobj(resp, fh)
