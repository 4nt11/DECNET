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
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Final

from mitreattack.stix20 import MitreAttackData

from decnet.ttp.attack_version import (
    ATTACK_BUNDLE_SHA256,
    ATTACK_BUNDLE_URL,
    ATTACK_BUNDLE_VERSION,
    ATTACK_LICENSE_FILENAME,
    ATTACK_LICENSE_SHA256,
    ATTACK_LICENSE_URL,
)

logger = logging.getLogger(__name__)

_ENV_BUNDLE_PATH: Final[str] = "DECNET_ATTACK_BUNDLE"
_ENV_LICENSE_PATH: Final[str] = "DECNET_ATTACK_LICENSE"
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


def _expected_license_path() -> Path:
    return _cache_dir() / ATTACK_LICENSE_FILENAME


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_sha256(path: Path) -> None:
    actual = _sha256(path)
    if actual != ATTACK_BUNDLE_SHA256:
        raise AttackBundleError(
            f"ATT&CK bundle at {path} sha256={actual} does not match "
            f"pinned {ATTACK_BUNDLE_SHA256} (version {ATTACK_BUNDLE_VERSION}). "
            "Refusing to load — re-fetch or update attack_version.py."
        )


def _download(url: str, target: Path, *, label: str) -> None:
    import requests

    target.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Fetching %s %s -> %s", label, url, target)
    tmp = target.with_suffix(target.suffix + ".part")
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        with tmp.open("wb") as f:
            for chunk in resp.iter_content(1 << 20):
                if chunk:
                    f.write(chunk)
        tmp.replace(target)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _fetch_bundle(target: Path) -> None:
    _download(ATTACK_BUNDLE_URL, target, label="ATT&CK bundle")


def _fetch_license(target: Path) -> None:
    """Fetch MITRE's LICENSE.txt. Hash mismatch is logged + re-fetched, never fail-closed.

    The ATT&CK bundle is fail-closed because a tampered bundle would
    silently mistag thousands of events. The license is required by
    the Terms of Use *to be present*; an upstream formatting tweak
    isn't a security event, so we resync rather than refuse to boot.
    """
    _download(ATTACK_LICENSE_URL, target, label="ATT&CK license")
    actual = _sha256(target)
    if actual != ATTACK_LICENSE_SHA256:
        logger.warning(
            "ATT&CK LICENSE.txt sha256=%s differs from pinned %s — "
            "MITRE may have updated the license text. Update "
            "ATTACK_LICENSE_SHA256 in attack_version.py if intentional.",
            actual,
            ATTACK_LICENSE_SHA256,
        )


def _ensure_license(cache_dir: Path) -> Path:
    """Return the path to a present LICENSE.txt, fetching if missing.

    Honors ``DECNET_ATTACK_LICENSE`` for operator-controlled overrides
    (mirrors ``DECNET_ATTACK_BUNDLE`` for offline / air-gapped installs).
    Refuses to return without a license file on disk — this is the
    compliance ratchet enforcing MITRE's Terms of Use.
    """
    override = os.environ.get(_ENV_LICENSE_PATH)
    if override:
        path = Path(override)
        if not path.is_file():
            raise AttackBundleError(
                f"{_ENV_LICENSE_PATH}={override} does not point to a file. "
                "MITRE's ATT&CK Terms of Use require the license to be "
                "present alongside any cached copy of ATT&CK data."
            )
        return path

    license_path = cache_dir / ATTACK_LICENSE_FILENAME
    if not license_path.is_file():
        _fetch_license(license_path)
    if not license_path.is_file():
        raise AttackBundleError(
            f"ATT&CK license missing at {license_path}. MITRE's ATT&CK "
            "Terms of Use require the license to be present alongside "
            "any cached copy of ATT&CK data. Run "
            "`python -m decnet.ttp.attack_stix fetch` or set "
            f"{_ENV_LICENSE_PATH} to an existing LICENSE.txt."
        )
    return license_path


def resolve_bundle_path() -> Path:
    """Return the verified bundle path, fetching the bundle and LICENSE if necessary.

    Both files must be present on disk before this returns. When
    ``DECNET_ATTACK_BUNDLE`` overrides the bundle path the license
    must live next to that bundle, or be reachable via
    ``DECNET_ATTACK_LICENSE``. The cache dir is checked first so
    operator-supplied bundles can still rely on the auto-cached
    license.
    """
    override = os.environ.get(_ENV_BUNDLE_PATH)
    if override:
        path = Path(override)
        if not path.is_file():
            raise AttackBundleError(
                f"{_ENV_BUNDLE_PATH}={override} does not point to a file"
            )
        _verify_sha256(path)
        # License must accompany an override bundle. Check next to the
        # bundle first, then DECNET_ATTACK_LICENSE, then the cache dir
        # as a last resort.
        sibling = path.parent / ATTACK_LICENSE_FILENAME
        if sibling.is_file() or os.environ.get(_ENV_LICENSE_PATH):
            _ensure_license(path.parent)
        else:
            _ensure_license(_cache_dir())
        return path

    cached = _expected_cache_path()
    if not cached.is_file():
        _fetch_bundle(cached)
    _verify_sha256(cached)
    _ensure_license(_cache_dir())
    return cached


def loaded_license_path() -> Path | None:
    """Return the path to the on-disk LICENSE.txt this process is operating under.

    Resolution mirrors :func:`_ensure_license` but is read-only — it
    never fetches. Useful for the ``license`` CLI subcommand and for
    operators auditing what license text they accepted.
    """
    override = os.environ.get(_ENV_LICENSE_PATH)
    if override:
        p = Path(override)
        return p if p.is_file() else None
    bundle_override = os.environ.get(_ENV_BUNDLE_PATH)
    if bundle_override:
        sibling = Path(bundle_override).parent / ATTACK_LICENSE_FILENAME
        if sibling.is_file():
            return sibling
    cached = _cache_dir() / ATTACK_LICENSE_FILENAME
    return cached if cached.is_file() else None


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


def mitre_url_for(technique_id: str | None) -> str | None:
    """Return the canonical attack.mitre.org URL for *technique_id*, or None.

    Pulled from ``external_references[source_name="mitre-attack"].url``
    on the cached attack-pattern. Reuses the lru-cached
    :func:`_attack_pattern_by_id` so per-call cost is constant after
    first hit. ``None`` for unknown / missing IDs — callers must
    handle nullability (the column is ``Optional`` everywhere it
    surfaces).
    """
    if not technique_id:
        return None
    obj = _attack_pattern_by_id(technique_id)
    if obj is None:
        return None
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            url = ref.get("url")
            return url if isinstance(url, str) else None
    return None


@dataclass(frozen=True)
class GroupRef:
    """A single MITRE ATT&CK ``intrusion-set`` (group) reference.

    Returned by :func:`groups_using_technique` to surface "groups
    MITRE has documented as using this technique". Read-only —
    explicitly *not* an attribution claim about a DECNET attacker.
    """

    group_id: str  # e.g. "G0001"
    name: str
    aliases: tuple[str, ...]
    mitre_url: str | None  # https://attack.mitre.org/groups/G0001


def _group_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            return ext if isinstance(ext, str) else None
    return None


def _group_mitre_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            url = ref.get("url")
            return url if isinstance(url, str) else None
    return None


@lru_cache(maxsize=4096)
def groups_using_technique(technique_id: str) -> tuple[GroupRef, ...]:
    """Groups MITRE has documented as using *technique_id* — exact-match, deterministic order.

    Sub-techniques are queried directly and do **not** union their
    parent's groups (matching ATT&CK Navigator semantics). Callers
    that want a broader view can resolve the parent themselves via
    :func:`subtechnique_parent_name`.

    Returns an empty tuple if the technique is unknown or has no
    ``uses`` relationships in the loaded bundle. Groups are sorted
    by group_id ascending so JSON responses are stable across runs.
    """
    if not technique_id:
        return ()
    obj = _attack_pattern_by_id(technique_id)
    if obj is None:
        return ()
    raw = _load().get_groups_using_technique(obj["id"])
    refs: list[GroupRef] = []
    for entry in raw:
        # mitreattack-python returns [{"object": IntrusionSet, "relationships": [...]}]
        sdo = entry.get("object") if isinstance(entry, dict) else entry
        if sdo is None:
            continue
        gid = _group_external_id(sdo)
        if gid is None:
            continue
        aliases = sdo.get("aliases") or ()
        refs.append(
            GroupRef(
                group_id=gid,
                name=sdo.get("name", gid),
                aliases=tuple(a for a in aliases if isinstance(a, str)),
                mitre_url=_group_mitre_url(sdo),
            )
        )
    refs.sort(key=lambda g: g.group_id)
    return tuple(refs)


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
    license_path = _expected_license_path()
    if not cached.is_file():
        try:
            _fetch_bundle(cached)
        except Exception as exc:  # pragma: no cover - network failure path
            print(f"bundle fetch failed: {exc}", file=sys.stderr)
            return 1
    if not license_path.is_file():
        try:
            _fetch_license(license_path)
        except Exception as exc:  # pragma: no cover - network failure path
            print(f"license fetch failed: {exc}", file=sys.stderr)
            return 1
    if print_sha:
        print(f"{_sha256(cached)}  {cached}")
        print(f"{_sha256(license_path)}  {license_path}")
        return 0
    try:
        _verify_sha256(cached)
    except AttackBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"OK {cached} (version {ATTACK_BUNDLE_VERSION})")
    print(f"OK {license_path}")
    return 0


def _cli_license() -> int:
    path = loaded_license_path()
    if path is None:
        print(
            "No ATT&CK LICENSE.txt found. Run `python -m decnet.ttp.attack_stix fetch`.",
            file=sys.stderr,
        )
        return 1
    print(path.read_text(encoding="utf-8"))
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m decnet.ttp.attack_stix")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser(
        "fetch", help="Fetch + verify the pinned ATT&CK bundle and LICENSE.txt."
    )
    f.add_argument(
        "--print-sha",
        action="store_true",
        help="Print sha256 of the cached files (for updating attack_version.py).",
    )
    sub.add_parser(
        "license",
        help="Print the cached MITRE ATT&CK LICENSE.txt to stdout.",
    )
    args = p.parse_args(argv)
    if args.cmd == "fetch":
        return _cli_fetch(args.print_sha)
    if args.cmd == "license":
        return _cli_license()
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
    "GroupRef",
    "groups_using_technique",
    "loaded_bundle_path",
    "loaded_license_path",
    "mitre_url_for",
    "resolve_bundle_path",
    "subtechnique_parent_name",
    "tactic_exists",
    "tactic_id_for_short_name",
    "tactic_name",
    "technique_exists",
    "technique_name",
]
