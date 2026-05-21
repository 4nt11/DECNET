"""RPKI validity enrichment — maps (IP, ASN) pairs to route origin validity.

Public surface:

* :func:`enrich_rpki` — takes an IP string and ASN int, returns
  ``(rpki_status, provider_name)`` or ``(None, None)``.

Validator selection goes through :func:`~decnet.rpki.factory.get_validator`
(env ``DECNET_RPKI_PROVIDER``, default ``ripestat``). Direct imports of
concrete validators are forbidden — mirrors the ``get_bus`` /
``get_repository`` rule.
"""
from __future__ import annotations

import os
from typing import Optional, Tuple

from decnet.rpki.factory import get_validator


def enrich_rpki(ip: str, asn: Optional[int]) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(rpki_status, provider_name)`` or ``(None, None)``.

    Never raises — any failure collapses to ``(None, None)`` so the
    caller (profiler) can upsert the attacker row regardless.

    Short-circuits to ``(None, None)`` when ``asn`` is None (no ASN
    means no route origin to validate) or when
    ``DECNET_RPKI_ENABLED=false``.
    """
    if os.environ.get("DECNET_RPKI_ENABLED", "true").lower() == "false":
        return (None, None)
    if asn is None:
        return (None, None)
    try:
        validator = get_validator()
        result = validator.validate(ip, asn)
        return (result.status, validator.name)
    except Exception:
        return (None, None)


__all__ = ["enrich_rpki"]
