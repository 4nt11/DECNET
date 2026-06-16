# SPDX-License-Identifier: AGPL-3.0-or-later
"""RIR provider — orchestrates fetch + parse into a :class:`Lookup`."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from decnet.geoip.base import Provider
from decnet.geoip.lookup import Lookup
from decnet.geoip.paths import ensure_root
from decnet.geoip.rir.fetch import RIR_SOURCES, fetch_all
from decnet.geoip.rir.parse import Range, parse_file

logger = logging.getLogger("decnet.geoip.rir.provider")

# Pickled lookup cache — skips re-parsing ~5 MB of RIR text on every
# profiler restart. Rebuilt whenever any raw file is newer than the
# cache, see ``_cache_fresh``.
_CACHE_NAME = ".rir_index.pkl"


class RirProvider(Provider):
    name = "rir"

    def __init__(self) -> None:
        self._root = ensure_root()

    # ---------- Provider interface ----------

    def refresh(self) -> None:
        logger.info("geoip.rir: refreshing delegated-stats files into %s", self._root)
        fetch_all(self._root)
        # Invalidate the cache — next build_lookup regenerates it.
        cache = self._root / _CACHE_NAME
        if cache.exists():
            cache.unlink(missing_ok=True)

    def build_lookup(self) -> Lookup:
        cache = self._root / _CACHE_NAME
        if self._cache_fresh(cache):
            try:
                lookup = Lookup.load(cache)
                logger.debug("geoip.rir: loaded cached index (%d ranges)", len(lookup))
                return lookup
            except Exception as exc:
                logger.warning("geoip.rir: cache load failed, rebuilding: %s", exc)

        ranges: list[Range] = []
        for path in self.data_paths():
            if not path.exists():
                continue
            ranges.extend(parse_file(path))
        lookup = Lookup.from_ranges(ranges)
        try:
            lookup.save(cache)
        except Exception as exc:
            logger.warning("geoip.rir: cache save failed: %s", exc)
        logger.info("geoip.rir: built index with %d ranges", len(lookup))
        return lookup

    def data_paths(self) -> Sequence[Path]:
        return [self._root / f"{name}.txt" for name, _url in RIR_SOURCES]

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
