"""STIX 2.1 backed MITRE ATT&CK lookups.

Replaces the hand-maintained technique-name dict that used to live in
``decnet/ttp/attack_catalog.py``. Single source of truth is the
official ``enterprise-attack-<version>.json`` STIX bundle published by
MITRE; consumers (rule engine, intel lifters, web router, frontend
rollups) call the small public API below instead of reading raw STIX.

Bundle resolution order
-----------------------

1. ``DECNET_ATTACK_BUNDLE`` env var (absolute path to a JSON file).
2. ``<cache_dir>/enterprise-attack-<version>.json`` where ``<cache_dir>``
   defaults to ``~/.cache/decnet/attack`` and is overridable with
   ``DECNET_ATTACK_CACHE_DIR``.
3. Fetch from :data:`decnet.ttp.attack_version.ATTACK_BUNDLE_URL` into
   the cache dir.

In every case the loaded bytes are verified against
:data:`decnet.ttp.attack_version.ATTACK_BUNDLE_SHA256` *before* the
bundle is parsed. A mismatch raises :class:`AttackBundleError` and the
loader refuses to serve queries. This is intentional — drift between
DECNET's expected ATT&CK version and what the operator (or a tampered
mirror) actually placed on disk would silently mistag thousands of
events.

Lazy-loading: the bundle (~50 MB) is parsed on first call to any
public function, never at import time. Tests that don't touch ATT&CK
should never pay the cost.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Final

from mitreattack.stix20 import MitreAttackData

from decnet.ttp.attack_version import (
    ATTACK_BUNDLE_SHA256,
    ATTACK_BUNDLE_URL,
    ATTACK_BUNDLE_VERSION,
)

logger = logging.getLogger(__name__)

_ENV_BUNDLE_PATH: Final[str] = "DECNET_ATTACK_BUNDLE"
_ENV_CACHE_DIR: Final[str] = "DECNET_ATTACK_CACHE_DIR"
_DEFAULT_CACHE_DIR: Final[Path] = Path.home() / ".cache" / "decnet" / "attack"

_data_lock = Lock()
_data: MitreAttackData | None = None
_loaded_path: Path | None = None


class AttackBundleError(RuntimeError):
    """Raised when the ATT&CK STIX bundle cannot be loaded or verified."""


def _cache_dir() -> Path:
    override = os.environ.get(_ENV_CACHE_DIR)
    return Path(override) if override else _DEFAULT_CACHE_DIR


def _expected_cache_path() -> Path:
    return _cache_dir() / f"enterprise-attack-{ATTACK_BUNDLE_VERSION}.json"


def _verify_sha256(path: Path) -> None:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != ATTACK_BUNDLE_SHA256:
        raise AttackBundleError(
            f"ATT&CK bundle at {path} sha256={actual} does not match "
            f"pinned {ATTACK_BUNDLE_SHA256} (version {ATTACK_BUNDLE_VERSION}). "
            "Refusing to load — re-fetch or update attack_version.py."
        )


def _fetch_bundle(target: Path) -> None:
    import requests

    target.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Fetching ATT&CK bundle %s -> %s", ATTACK_BUNDLE_URL, target)
    tmp = target.with_suffix(target.suffix + ".part")
    try:
        resp = requests.get(ATTACK_BUNDLE_URL, timeout=60, stream=True)
        resp.raise_for_status()
        with tmp.open("wb") as f:
            for chunk in resp.iter_content(1 << 20):
                if chunk:
                    f.write(chunk)
        tmp.replace(target)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def resolve_bundle_path() -> Path:
    """Return the verified bundle path, fetching if necessary."""
    override = os.environ.get(_ENV_BUNDLE_PATH)
    if override:
        path = Path(override)
        if not path.is_file():
            raise AttackBundleError(
                f"{_ENV_BUNDLE_PATH}={override} does not point to a file"
            )
        _verify_sha256(path)
        return path

    cached = _expected_cache_path()
    if not cached.is_file():
        _fetch_bundle(cached)
    _verify_sha256(cached)
    return cached


def _load() -> MitreAttackData:
    global _data, _loaded_path
    with _data_lock:
        if _data is not None:
            return _data
        path = resolve_bundle_path()
        _data = MitreAttackData(str(path))
        _loaded_path = path
        logger.info(
            "Loaded ATT&CK bundle version=%s path=%s",
            ATTACK_BUNDLE_VERSION,
            path,
        )
        return _data


def loaded_bundle_path() -> Path | None:
    """Return the path the bundle was loaded from, or ``None`` if not loaded yet."""
    return _loaded_path


@lru_cache(maxsize=4096)
def _attack_pattern_by_id(technique_id: str) -> dict | None:
    obj = _load().get_object_by_attack_id(technique_id, "attack-pattern")
    if obj is None:
        return None
    return dict(obj)


@lru_cache(maxsize=64)
def _tactic_by_id(tactic_id: str) -> dict | None:
    obj = _load().get_object_by_attack_id(tactic_id, "x-mitre-tactic")
    if obj is None:
        return None
    return dict(obj)


@lru_cache(maxsize=64)
def _tactic_by_short_name(short_name: str) -> dict | None:
    for obj in _load().get_tactics():
        if obj.get("x_mitre_shortname") == short_name:
            return dict(obj)
    return None


def technique_name(technique_id: str | None) -> str | None:
    """Return the canonical ATT&CK display name for *technique_id*.

    For a sub-technique (``T1059.004``) the parent is prepended so the
    rendered string matches the historical format
    ``"Command and Scripting Interpreter: Unix Shell"``. ``None`` for
    unknown IDs — callers (UI, exporter) fall back to showing the bare
    ID. Drift is caught at startup by
    :func:`assert_known_technique_ids`, so a ``None`` here in
    production means an upstream emitted an ID that wasn't on the
    validation list (likely a hot-loaded rule).
    """
    if not technique_id:
        return None
    obj = _attack_pattern_by_id(technique_id)
    if obj is None:
        return None
    name = obj.get("name")
    if "." not in technique_id or not obj.get("x_mitre_is_subtechnique"):
        return name
    parent = subtechnique_parent_name(technique_id)
    if parent is None:
        return name
    return f"{parent}: {name}"


def subtechnique_parent_name(technique_id: str) -> str | None:
    parents = _load().get_parent_technique_of_subtechnique(
        _attack_pattern_by_id(technique_id)["id"]  # type: ignore[index]
    )
    if not parents:
        return None
    return parents[0]["object"].name


def is_subtechnique(technique_id: str) -> bool:
    obj = _attack_pattern_by_id(technique_id)
    return bool(obj and obj.get("x_mitre_is_subtechnique"))


def tactic_name(tactic_id_or_short_name: str | None) -> str | None:
    """Return the tactic display name for either a ``TA0001``-style ID or a kill-chain short name."""
    if not tactic_id_or_short_name:
        return None
    if tactic_id_or_short_name.startswith("TA"):
        obj = _tactic_by_id(tactic_id_or_short_name)
    else:
        obj = _tactic_by_short_name(tactic_id_or_short_name)
    return obj.get("name") if obj else None


def tactic_id_for_short_name(short_name: str) -> str | None:
    obj = _tactic_by_short_name(short_name)
    if obj is None:
        return None
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def kill_chain_phases(technique_id: str) -> list[str]:
    """Return the kill-chain phase short-names for a technique."""
    obj = _attack_pattern_by_id(technique_id)
    if obj is None:
        return []
    return [
        p["phase_name"]
        for p in obj.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == "mitre-attack"
    ]


def technique_exists(technique_id: str) -> bool:
    return _attack_pattern_by_id(technique_id) is not None


def tactic_exists(tactic_id: str) -> bool:
    return _tactic_by_id(tactic_id) is not None


def assert_known_technique_ids(
    technique_ids: list[str] | set[str] | tuple[str, ...],
    *,
    source: str,
) -> None:
    """Raise :class:`AttackBundleError` listing any IDs missing from the bundle."""
    missing = sorted({t for t in technique_ids if t and not technique_exists(t)})
    if missing:
        raise AttackBundleError(
            f"{source}: technique IDs not present in ATT&CK Enterprise "
            f"v{ATTACK_BUNDLE_VERSION}: {missing}"
        )


def assert_known_tactic_ids(
    tactic_ids: list[str] | set[str] | tuple[str, ...],
    *,
    source: str,
    exempt: set[str] | None = None,
) -> None:
    exempt = exempt or set()
    missing = sorted(
        {t for t in tactic_ids if t and t not in exempt and not tactic_exists(t)}
    )
    if missing:
        raise AttackBundleError(
            f"{source}: tactic IDs not present in ATT&CK Enterprise "
            f"v{ATTACK_BUNDLE_VERSION}: {missing}"
        )


def _cli_fetch(print_sha: bool) -> int:
    cached = _expected_cache_path()
    if not cached.is_file():
        try:
            _fetch_bundle(cached)
        except Exception as exc:  # pragma: no cover - network failure path
            print(f"fetch failed: {exc}", file=sys.stderr)
            return 1
    if print_sha:
        h = hashlib.sha256()
        with cached.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        print(f"{h.hexdigest()}  {cached}")
        return 0
    try:
        _verify_sha256(cached)
    except AttackBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"OK {cached} (version {ATTACK_BUNDLE_VERSION})")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m decnet.ttp.attack_stix")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="Fetch and verify the pinned ATT&CK bundle.")
    f.add_argument(
        "--print-sha",
        action="store_true",
        help="Print sha256 of the cached bundle (for updating attack_version.py).",
    )
    args = p.parse_args(argv)
    if args.cmd == "fetch":
        return _cli_fetch(args.print_sha)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ATTACK_BUNDLE_VERSION",
    "AttackBundleError",
    "assert_known_tactic_ids",
    "assert_known_technique_ids",
    "is_subtechnique",
    "kill_chain_phases",
    "loaded_bundle_path",
    "resolve_bundle_path",
    "subtechnique_parent_name",
    "tactic_exists",
    "tactic_id_for_short_name",
    "tactic_name",
    "technique_exists",
    "technique_name",
]
