# SPDX-License-Identifier: AGPL-3.0-or-later
"""_build_record must thread ASN fields through to the upsert payload."""
from __future__ import annotations

import gzip
from datetime import datetime, timezone
from pathlib import Path

from decnet.correlation.parser import LogEvent
from decnet.profiler.worker import _build_record


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


def _seed(root: Path) -> None:
    target = root / "ip2asn-v4.tsv.gz"
    with gzip.open(target, "wt", encoding="utf-8") as fh:
        fh.write("8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n")


def test_build_record_includes_asn_when_resolved(tmp_path: Path) -> None:
    _seed(tmp_path)
    record = _build_record("8.8.8.8", [_evt("8.8.8.8")], None, [], [])
    assert record["asn"] == 15169
    assert record["as_name"] == "GOOGLE"
    assert record["asn_source"] == "iptoasn"


def test_build_record_asn_none_for_private(tmp_path: Path) -> None:
    _seed(tmp_path)
    record = _build_record("10.0.0.1", [_evt("10.0.0.1")], None, [], [])
    assert record["asn"] is None
    assert record["as_name"] is None
    assert record["asn_source"] is None


def test_build_record_asn_none_for_unannounced(tmp_path: Path) -> None:
    _seed(tmp_path)
    # 9.0.0.0 isn't in the seeded fixture range — no BGP origin we know of.
    record = _build_record("9.0.0.0", [_evt("9.0.0.0")], None, [], [])
    assert record["asn"] is None
