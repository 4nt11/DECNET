"""_build_record must thread RPKI fields through to the upsert payload."""
from __future__ import annotations

import gzip
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from decnet.correlation.parser import LogEvent
from decnet.profiler.worker import _build_record
from decnet.rpki.base import RpkiResult


def _evt(ip: str) -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 4, 23, tzinfo=timezone.utc),
        attacker_ip=ip,
        decky="decky-01",
        service="ssh",
        event_type="conn",
        fields={},
        raw="",
    )


def _seed_asn(root: Path) -> None:
    target = root / "ip2asn-v4.tsv.gz"
    with gzip.open(target, "wt", encoding="utf-8") as fh:
        fh.write("8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")


def test_build_record_includes_rpki_when_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_asn(tmp_path)

    def _stub_validate(self, ip: str, asn: int) -> RpkiResult:
        return RpkiResult(status="valid", prefix="8.8.8.0/24")

    with patch(
        "decnet.rpki.ripestat.validator.RipeStatValidator.validate",
        _stub_validate,
    ):
        record = _build_record("8.8.8.8", [_evt("8.8.8.8")], None, [], [])

    assert record["bgp_prefix"] == "8.8.8.0/24"
    assert record["rpki_status"] == "valid"
    assert record["rpki_source"] == "ripestat"


def test_build_record_rpki_none_for_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_asn(tmp_path)
    record = _build_record("10.0.0.1", [_evt("10.0.0.1")], None, [], [])
    assert record["rpki_status"] is None
    assert record["rpki_source"] is None


def test_build_record_rpki_unknown_on_network_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_asn(tmp_path)

    def _fail(self, ip: str, asn: int) -> RpkiResult:
        raise OSError("connection refused")

    with patch(
        "decnet.rpki.ripestat.validator.RipeStatValidator.validate",
        _fail,
    ):
        record = _build_record("8.8.8.8", [_evt("8.8.8.8")], None, [], [])

    # enrich_rpki wraps the validator — any exception collapses to (None, None)
    assert record["rpki_status"] is None
    assert record["rpki_source"] is None
