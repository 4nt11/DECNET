"""iptoasn provider — orchestrates fetch + parse into an :class:`AsnLookup`.

Mirrors :class:`decnet.geoip.rir.provider.RirProvider` exactly: fetch,
build a pickled cache, invalidate when raw files are newer than the
cache.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from decnet.asn.base import Provider
from decnet.asn.iptoasn.fetch import IPTOASN_SOURCES, fetch_all
from decnet.asn.iptoasn.parse import parse_file
from decnet.asn.lookup import AsnLookup, Range
from decnet.asn.paths import ensure_root

logger = logging.getLogger("decnet.asn.iptoasn.provider")

# Pickled lookup cache — skips re-parsing the ~580k-row gz dump on every
# profiler restart. Rebuilt whenever any raw file is newer than the
# cache, see ``_cache_fresh``.
_CACHE_NAME = ".iptoasn_index.pkl"


class IptoasnProvider(Provider):
    name = "iptoasn"

    def __init__(self) -> None:
        self._root = ensure_root()

    # ---------- Provider interface ----------

    def refresh(self) -> None:
        logger.info("asn.iptoasn: refreshing dump into %s", self._root)
        fetch_all(self._root)
        cache = self._root / _CACHE_NAME
        if cache.exists():
            cache.unlink(missing_ok=True)

    def build_lookup(self) -> AsnLookup:
        cache = self._root / _CACHE_NAME
        if self._cache_fresh(cache):
            try:
                lookup = AsnLookup.load(cache)
                logger.debug(
                    "asn.iptoasn: loaded cached index (%d ranges)",
                    len(lookup),
                )
                return lookup
            except Exception as exc:
                logger.warning(
                    "asn.iptoasn: cache load failed, rebuilding: %s", exc
                )

        ranges: list[Range] = []
        for path in self.data_paths():
            if not path.exists():
                continue
            ranges.extend(parse_file(path))
        lookup = AsnLookup.from_ranges(ranges)
        try:
            lookup.save(cache)
        except Exception as exc:
            logger.warning("asn.iptoasn: cache save failed: %s", exc)
        logger.info("asn.iptoasn: built index with %d ranges", len(lookup))
        return lookup

    def data_paths(self) -> Sequence[Path]:
        return [self._root / f"{name}.tsv.gz" for name, _url in IPTOASN_SOURCES]

    # ---------- internals ----------

    def _cache_fresh(self, cache: Path) -> bool:
        """True when the pickle exists and is at least as new as every raw file."""
        if not cache.exists():
            return False
        cache_mtime = cache.stat().st_mtime
        for path in self.data_paths():
            if path.exists() and path.stat().st_mtime > cache_mtime:
                return False
        return True
