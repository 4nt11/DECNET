# SPDX-License-Identifier: AGPL-3.0-or-later
"""YAML-backed loader for intel-provider → ATT&CK technique mappings.

Replaces the ``_*_TO_TECHNIQUES`` ``Final[dict]`` tables that used to
live in :mod:`decnet.ttp.impl.intel_lifter`. Source-of-truth files
live under :mod:`decnet.ttp.data.intel` (one YAML per provider) and
are validated against the loaded ATT&CK STIX bundle at load time:

* every ``technique_id`` in every signal must resolve in
  :func:`decnet.ttp.attack_stix.technique_exists`
* every entry is enriched with the canonical MITRE
  ``external_reference`` (source_name=``mitre-attack``, url) so the
  future STIX/MISP exporter can emit fully-resolved relationship
  objects without a second mapping pass

Design constraint: this module is the only place provider-mapping
schema knowledge lives. ``intel_lifter`` reads :class:`ProviderMapping`
accessors and never touches the dicts directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from decnet.ttp import attack_stix

_DATA_DIR: Path = Path(__file__).parent / "intel"


# ─── YAML schema (pydantic v2) ─────────────────────────────────────


class ExternalReference(BaseModel):
    """STIX 2.1 ``external-reference`` shape — kept faithful so the
    future STIX exporter is a direct translation."""

    model_config = ConfigDict(frozen=True)

    source_name: str
    url: str
    external_id: str | None = None


class TechniqueEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    technique_id: str
    # Per-technique gate: emission only fires when an upstream
    # confidence score (e.g. AbuseIPDB ``abuseConfidenceScore``)
    # meets or exceeds this floor. None = always fire.
    high_score_threshold: int | None = None


class SignalEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    external_reference: ExternalReference
    techniques: tuple[TechniqueEntry, ...]
    confidence_multiplier: float = 1.0


class ProviderMappingFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str
    mapping_version: str
    attack_release: str = Field(
        description="Minimum ATT&CK release this mapping is known-correct against."
    )
    signals: tuple[SignalEntry, ...]


# ─── Runtime accessor objects ──────────────────────────────────────


@dataclass(frozen=True)
class TechniqueEmission:
    """A single emit slot for a (signal, technique) pair, enriched with the canonical MITRE URL."""

    technique_id: str
    high_score_threshold: int | None
    mitre_url: str | None


@dataclass(frozen=True)
class Signal:
    id: str
    label: str
    external_reference: ExternalReference
    emissions: tuple[TechniqueEmission, ...]
    confidence_multiplier: float

    def technique_ids(self) -> frozenset[str]:
        return frozenset(e.technique_id for e in self.emissions)


@dataclass(frozen=True)
class ProviderMapping:
    provider: str
    mapping_version: str
    signals: tuple[Signal, ...]
    _by_id: dict[str, Signal]

    def get(self, signal_id: str) -> Signal | None:
        return self._by_id.get(signal_id)

    def techniques_for_signal(
        self, signal_id: str, *, score: float | None = None
    ) -> frozenset[TechniqueEmission]:
        """Emissions a given signal produces, filtered by ``score``-vs-threshold gate.

        ``score`` is the upstream confidence (e.g. AbuseIPDB
        ``abuseConfidenceScore`` 0-100). If a technique has a
        ``high_score_threshold`` and ``score`` is below it (or
        unknown), that technique is filtered out. Mirrors the legacy
        ``_ABUSEIPDB_HIGH_SCORE_GATED`` semantics.
        """
        sig = self._by_id.get(signal_id)
        if sig is None:
            return frozenset()
        out: set[TechniqueEmission] = set()
        for emission in sig.emissions:
            if emission.high_score_threshold is not None:
                if score is None or score < emission.high_score_threshold:
                    continue
            out.add(emission)
        return frozenset(out)

    def all_technique_ids(self) -> frozenset[str]:
        return frozenset(
            e.technique_id for sig in self.signals for e in sig.emissions
        )

    def signal_ids(self) -> frozenset[str]:
        return frozenset(self._by_id.keys())


# ─── Loader ────────────────────────────────────────────────────────


def _mitre_url_for(technique_id: str) -> str | None:
    """Compatibility shim — collapsed to a re-export of :func:`attack_stix.mitre_url_for`.

    Public callers should import :func:`decnet.ttp.attack_stix.mitre_url_for`
    directly. Kept here so the in-tree loader stays self-contained
    when someone reads it cold.
    """
    return attack_stix.mitre_url_for(technique_id)


def _data_path(provider: str) -> Path:
    return _DATA_DIR / f"{provider}.yaml"


@lru_cache(maxsize=8)
def load_provider_mapping(provider: str) -> ProviderMapping:
    """Load + validate + enrich a provider's mapping YAML. Cached process-wide."""
    path = _data_path(provider)
    if not path.is_file():
        raise FileNotFoundError(
            f"intel mapping for provider {provider!r} not found at {path}"
        )
    raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    parsed = ProviderMappingFile.model_validate(raw)
    if parsed.provider != provider:
        raise ValueError(
            f"{path}: provider field {parsed.provider!r} does not match "
            f"filename {provider!r}"
        )

    # Validate every technique resolves in the loaded ATT&CK bundle.
    all_ids = sorted(
        {t.technique_id for s in parsed.signals for t in s.techniques}
    )
    attack_stix.assert_known_technique_ids(
        all_ids, source=f"decnet/ttp/data/intel/{provider}.yaml"
    )

    signals: list[Signal] = []
    for s in parsed.signals:
        emissions = tuple(
            TechniqueEmission(
                technique_id=t.technique_id,
                high_score_threshold=t.high_score_threshold,
                mitre_url=_mitre_url_for(t.technique_id),
            )
            for t in s.techniques
        )
        signals.append(
            Signal(
                id=s.id,
                label=s.label,
                external_reference=s.external_reference,
                emissions=emissions,
                confidence_multiplier=s.confidence_multiplier,
            )
        )
    by_id = {s.id: s for s in signals}
    if len(by_id) != len(signals):
        dupes = [s.id for s in signals if list(by_id).count(s.id) > 1]
        raise ValueError(f"{path}: duplicate signal ids: {dupes}")

    return ProviderMapping(
        provider=parsed.provider,
        mapping_version=parsed.mapping_version,
        signals=tuple(signals),
        _by_id=by_id,
    )


def clear_cache() -> None:
    """Drop cached :class:`ProviderMapping` instances. Test-only knob."""
    load_provider_mapping.cache_clear()


__all__ = [
    "ExternalReference",
    "ProviderMapping",
    "Signal",
    "TechniqueEmission",
    "clear_cache",
    "load_provider_mapping",
]
