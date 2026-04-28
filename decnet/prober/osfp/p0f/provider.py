"""p0f v2 Provider — loads the vendored .fp databases and matches
against observed TCP quirks.

Four databases ship under ``data/``:

    p0f.fp   — SYN fingerprints (passive / sniffer-captured inbound).
    p0fa.fp  — SYN-ACK fingerprints (prober active-probe responses).
    p0fr.fp  — RST+ fingerprints (reset-response quirks).
    p0fo.fp  — "stray" packet fingerprints.

The provider routes incoming observations to the right sig list based
on ``obs["context"]`` — see :meth:`P0fV2Provider.match` — and returns
the highest-specificity matching :class:`OsMatch` or ``None``.

DECNET-authored additions can land in ``p0f-decnet.fp`` (same
directory, loaded if present) under GPL-3.0. None exist today — the
plan deferred writing any to a later commit — but the provider
already picks it up when it appears.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from decnet.prober.osfp.base import OsMatch, Provider
from decnet.prober.osfp.p0f.format import parse_p0f_v2
from decnet.prober.osfp.p0f.signature import Signature

logger = logging.getLogger("decnet.prober.osfp.p0f.provider")


# Directory containing the vendored .fp files.
_DATA_DIR: Path = Path(__file__).resolve().parent / "data"

# Which .fp files feed each observation context.
_CONTEXT_DBS: dict[str, tuple[str, ...]] = {
    "syn":    ("p0f.fp", "p0f-decnet.fp"),
    "synack": ("p0fa.fp",),
    "rst":    ("p0fr.fp",),
    "stray":  ("p0fo.fp",),
}


class P0fV2Provider(Provider):
    """Match observations against the p0f v2 database."""

    name = "p0f-v2"

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self._data_dir = (data_dir or _DATA_DIR).resolve()
        self._sigs_by_context: dict[str, list[Signature]] = {}
        self._load()

    def _load(self) -> None:
        for context, filenames in _CONTEXT_DBS.items():
            merged: list[Signature] = []
            for name in filenames:
                path = self._data_dir / name
                if not path.is_file():
                    # p0f-decnet.fp is optional; all others are required.
                    if name.startswith("p0f-decnet"):
                        continue
                    logger.warning("p0f-v2: missing required DB file %s", path)
                    continue
                try:
                    merged.extend(parse_p0f_v2(path))
                except OSError as exc:
                    logger.warning("p0f-v2: could not load %s: %s", path, exc)
            self._sigs_by_context[context] = merged
            logger.debug("p0f-v2: %s context loaded %d signatures", context, len(merged))

    def match(self, obs: dict[str, Any]) -> Optional[OsMatch]:
        """Return the highest-specificity matching signature, or None.

        ``obs["context"]`` selects the DB slice; default is "syn"
        (passive observation, which is 80%+ of the event stream).
        Invalid contexts return None rather than raising.
        """
        context = obs.get("context", "syn")
        sigs = self._sigs_by_context.get(context)
        if not sigs:
            return None

        best: tuple[float, Signature] | None = None
        for sig in sigs:
            score = sig.score(obs)
            if score is None:
                continue
            if best is None or score > best[0]:
                best = (score, sig)
            # Short-circuit on a perfect match — can't beat 1.0.
            if best[0] >= 1.0:
                break

        if best is None:
            return None
        score, sig = best
        return OsMatch(
            os=sig.os,
            flavor=sig.flavor,
            confidence=score,
            provider=self.name,
            is_userland=sig.is_userland,
        )

    def signature_counts(self) -> dict[str, int]:
        """For diagnostics / tests — how many sigs loaded per context."""
        return {ctx: len(sigs) for ctx, sigs in self._sigs_by_context.items()}
