"""RipeStatValidator HTTP + cache integration tests.

All network calls are intercepted via monkeypatching
``urllib.request.urlopen`` so no real HTTP leaves the test runner.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _mock_urlopen(responses: dict[str, Any]):
    """Return a context-manager mock for urlopen that dispatches by URL fragment."""

    def _urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for fragment, payload in responses.items():
            if fragment in url:
                body = json.dumps(payload).encode()
                mock = MagicMock()
                mock.__enter__ = lambda s: io.BytesIO(body)
                mock.__exit__ = MagicMock(return_value=False)
                return mock
        raise ValueError(f"Unexpected URL in test: {url}")

    return _urlopen


_NETWORK_INFO_VALID = {
    "data": {"prefix": "8.8.8.0/24", "asns": ["15169"]}
}
_RPKI_VALID = {
    "data": {"status": "valid", "validating_roas": []}
}
_RPKI_INVALID = {
    "data": {"status": "invalid", "validating_roas": []}
}
_RPKI_NOT_FOUND = {
    "data": {"status": "not-found", "validating_roas": []}
}
_NETWORK_INFO_EMPTY = {"data": {"prefix": None}}


@pytest.fixture()
def validator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DECNET_RPKI_ROOT", str(tmp_path))
    # Re-import to pick up the patched root
    import importlib
    import decnet.rpki.paths as rpki_paths
    monkeypatch.setattr(rpki_paths, "RPKI_ROOT", tmp_path)

    from decnet.rpki.ripestat.validator import RipeStatValidator
    return RipeStatValidator()


def test_valid_result(validator) -> None:
    responses = {
        "network-info": _NETWORK_INFO_VALID,
        "rpki-validation": _RPKI_VALID,
    }
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        result = validator.validate("8.8.8.8", 15169)
    assert result.status == "valid"
    assert result.prefix == "8.8.8.0/24"


def test_invalid_result(validator) -> None:
    responses = {
        "network-info": _NETWORK_INFO_VALID,
        "rpki-validation": _RPKI_INVALID,
    }
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        result = validator.validate("8.8.8.8", 64496)
    assert result.status == "invalid"


def test_not_found_when_no_prefix(validator) -> None:
    responses = {"network-info": _NETWORK_INFO_EMPTY}
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        result = validator.validate("192.0.2.1", 64496)
    assert result.status == "not-found"


def test_unknown_on_network_error(validator) -> None:
    with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
        result = validator.validate("8.8.8.8", 15169)
    assert result.status == "unknown"


def test_cache_hit_skips_http(validator) -> None:
    responses = {
        "network-info": _NETWORK_INFO_VALID,
        "rpki-validation": _RPKI_VALID,
    }
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)) as mock:
        validator.validate("8.8.8.8", 15169)
        validator.validate("8.8.8.8", 15169)  # second call — should hit cache
    # urlopen called exactly twice (once per endpoint on the first call)
    assert mock.call_count == 2


def test_rpki_not_found_status_stored(validator) -> None:
    responses = {
        "network-info": _NETWORK_INFO_VALID,
        "rpki-validation": _RPKI_NOT_FOUND,
    }
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        result = validator.validate("8.8.8.8", 99999)
    assert result.status == "not-found"


def test_unknown_status_normalised(validator) -> None:
    """Any unrecognised status string from RIPE STAT collapses to 'unknown'."""
    responses = {
        "network-info": _NETWORK_INFO_VALID,
        "rpki-validation": {"data": {"status": "something-new"}},
    }
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        result = validator.validate("8.8.8.8", 15169)
    assert result.status == "unknown"
