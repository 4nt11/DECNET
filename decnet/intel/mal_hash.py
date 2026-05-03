"""MalwareBazaar bad-hash provider — bulk SHA-256 feed.

Mirrors :mod:`decnet.intel.feodo` for the refresh / TTL / set-membership
shape, but operates on the SHA-256 keyspace instead of IPs and so
implements :class:`decnet.intel.base.MalHashProvider` rather than
:class:`IntelProvider`. Keep the two ABCs disjoint — see ``base.py``.

Endpoint: ``GET https://bazaar.abuse.ch/export/csv/full/`` with
``Auth-Key: <key>`` header. Returns a ZIP'd CSV with one row per
sample; the ``sha256_hash`` column is the natural key. ~900K rows ≈
30 MB resident as a ``set[str]`` of hex-lowercased hashes.

Auth-key is read from ``DECNET_MALWAREBAZAAR_AUTH_KEY``. When unset,
the provider logs one warning at first refresh attempt and disables
itself for the process lifetime — :meth:`is_known_bad` returns ``False``
without ever making a network call. The ingester treats that the same
as "no opinion," so R0046's ``mal_hash_match`` lane stays absent on the
bus payload (which is exactly what the predicate's ``is True`` check
does today, so the silent-no-op is behaviorally identical to "lane not
shipped yet").
"""
from __future__ import annotations

import csv
import io
import os
import time
import zipfile
from typing import Optional

from decnet.intel.base import MalHashProvider
from decnet.logging import get_logger
from decnet.net.http import stealth_client

log = get_logger("intel.mal_hash")

_ENDPOINT = "https://bazaar.abuse.ch/export/csv/full/"
_DEFAULT_REFRESH_S = 86_400.0  # 24h — feed is daily, no need to hammer
_AUTH_KEY_ENV = "DECNET_MALWAREBAZAAR_AUTH_KEY"
_REFRESH_INTERVAL_ENV = "DECNET_MAL_HASH_REFRESH_INTERVAL_S"


def _read_refresh_interval() -> float:
    raw = os.environ.get(_REFRESH_INTERVAL_ENV)
    if raw is None:
        return _DEFAULT_REFRESH_S
    try:
        return float(raw)
    except ValueError:
        log.warning(
            "%s=%r not a float; falling back to default %.0f",
            _REFRESH_INTERVAL_ENV, raw, _DEFAULT_REFRESH_S,
        )
        return _DEFAULT_REFRESH_S


class MalwareBazaarProvider(MalHashProvider):
    """Bulk SHA-256 lookup against MalwareBazaar's full export."""

    name = "malwarebazaar"

    def __init__(
        self,
        *,
        auth_key: Optional[str] = None,
        refresh_interval_s: Optional[float] = None,
    ) -> None:
        self._auth_key = auth_key or os.environ.get(_AUTH_KEY_ENV) or None
        self._refresh_interval_s = (
            refresh_interval_s
            if refresh_interval_s is not None
            else _read_refresh_interval()
        )
        self._known: set[str] = set()
        self._loaded_at: float = 0.0
        self._last_error: Optional[str] = None
        self._disabled_warned: bool = False

    @property
    def disabled(self) -> bool:
        return self._auth_key is None

    async def _refresh(self) -> Optional[str]:
        """Refetch the bulk feed. Returns an error string or ``None``."""
        if self._auth_key is None:
            return "no auth key"
        try:
            async with stealth_client(timeout=60.0) as client:
                resp = await client.get(
                    _ENDPOINT, headers={"Auth-Key": self._auth_key},
                )
        except Exception as exc:  # noqa: BLE001
            return f"network: {exc}"
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        body = resp.content
        try:
            new_known = _parse_dump(body)
        except Exception as exc:  # noqa: BLE001
            return f"parse: {exc}"
        if not new_known:
            return "feed: empty"
        self._known = new_known
        self._loaded_at = time.monotonic()
        self._last_error = None
        log.info("malwarebazaar: refreshed bulk feed entries=%d", len(new_known))
        return None

    async def _ensure_fresh(self) -> None:
        if self.disabled:
            if not self._disabled_warned:
                log.warning(
                    "R0046 mal_hash_match disabled: %s unset",
                    _AUTH_KEY_ENV,
                )
                self._disabled_warned = True
            return
        if (
            not self._known
            or (time.monotonic() - self._loaded_at) >= self._refresh_interval_s
        ):
            err = await self._refresh()
            if err:
                self._last_error = err
                log.warning("malwarebazaar refresh failed: %s", err)

    async def is_known_bad(self, sha256: str) -> bool:
        if self.disabled:
            return False
        try:
            await self._ensure_fresh()
        except Exception as exc:  # noqa: BLE001
            # Belt and braces: _ensure_fresh swallows refresh failures
            # but a bug in there shouldn't blow up the ingester payload.
            log.exception("malwarebazaar refresh raised: %s", exc)
            return False
        return sha256.lower() in self._known


def _parse_dump(body: bytes) -> set[str]:
    """Extract SHA-256 hashes from MalwareBazaar's full dump.

    The endpoint returns a ZIP archive containing a single CSV with a
    ``sha256_hash`` column. Some abuse.ch flavours of the same feed
    family ship plain CSV instead — handle both by sniffing the magic
    bytes. Hashes are lowercased; non-hex / wrong-length values are
    dropped (defense in depth — we set-membership-test by exact match).
    """
    if body[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            csv_names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
            if not csv_names:
                raise ValueError("zip has no .csv member")
            with zf.open(csv_names[0]) as fh:
                csv_bytes = fh.read()
    else:
        csv_bytes = body
    text = csv_bytes.decode("utf-8", errors="replace")
    return _extract_hashes(text)


def _extract_hashes(text: str) -> set[str]:
    """Pull the ``sha256_hash`` column out of MalwareBazaar's CSV.

    The dump prefaces the table with ``#``-prefixed comment lines.
    Skip those, find the header row, locate the column, then read the
    rest. csv.reader handles the quoting (the ``signature`` column
    contains commas and is properly quoted in the dump).
    """
    body_lines = [
        line for line in text.splitlines()
        if line and not line.lstrip().startswith("#")
    ]
    if not body_lines:
        return set()
    reader = csv.reader(body_lines)
    header = next(reader, None)
    if not header:
        return set()
    norm = [h.strip().strip('"').lower() for h in header]
    try:
        col = norm.index("sha256_hash")
    except ValueError:
        # Fallback — first column is sha256 in every documented
        # variant; if the header naming changes upstream we still
        # capture something rather than silently emptying the set.
        col = 0
    out: set[str] = set()
    for row in reader:
        if len(row) <= col:
            continue
        cell = row[col].strip().strip('"').lower()
        if len(cell) == 64 and all(c in "0123456789abcdef" for c in cell):
            out.add(cell)
    return out
