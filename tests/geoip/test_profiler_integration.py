# SPDX-License-Identifier: AGPL-3.0-or-later
"""_build_record must thread country fields through to the upsert payload."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from decnet.correlation.parser import LogEvent
from decnet.geoip.rir.fetch import RIR_SOURCES
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


def test_build_record_includes_country_when_resolved(tmp_path: Path) -> None:
    (tmp_path / f"{RIR_SOURCES[0][0]}.txt").write_text(
        "arin|US|ipv4|8.8.8.0|256|20000101|allocated|abc\n"
    )
    record = _build_record("8.8.8.8", [_evt("8.8.8.8")], None, [], [])
    assert record["country_code"] == "US"
    assert record["country_source"] == "rir"


def test_build_record_country_none_for_private(tmp_path: Path) -> None:
    (tmp_path / f"{RIR_SOURCES[0][0]}.txt").write_text(
        "arin|US|ipv4|8.8.8.0|256|20000101|allocated|abc\n"
    )
    record = _build_record("10.0.0.1", [_evt("10.0.0.1")], None, [], [])
    assert record["country_code"] is None
    assert record["country_source"] is None
