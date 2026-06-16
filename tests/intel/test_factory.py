# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the intel provider factory.

The factory returns a **list** of configured providers (not a singleton
like :mod:`decnet.geoip.factory`). Coverage:

* disabled master switch returns ``[]``
* empty provider list returns ``[]``
* unknown provider name raises ``ValueError`` (typo guard)
* trimming + case-insensitivity of the providers env var
"""
from __future__ import annotations

import pytest

from decnet.intel.factory import get_intel_providers


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    # Disable real providers — concrete impls land in later commits, but
    # the factory tests should pass against whatever subset exists today
    # via empty/unknown lists.
    for key in (
        "DECNET_INTEL_ENABLED",
        "DECNET_INTEL_PROVIDERS",
        "DECNET_GREYNOISE_API_KEY",
        "DECNET_ABUSEIPDB_API_KEY",
        "DECNET_THREATFOX_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def test_disabled_returns_empty(monkeypatch):
    monkeypatch.setenv("DECNET_INTEL_ENABLED", "false")
    monkeypatch.setenv("DECNET_INTEL_PROVIDERS", "greynoise")
    assert get_intel_providers() == []


def test_empty_provider_list_returns_empty(monkeypatch):
    monkeypatch.setenv("DECNET_INTEL_PROVIDERS", "")
    assert get_intel_providers() == []


def test_unknown_provider_name_raises(monkeypatch):
    monkeypatch.setenv("DECNET_INTEL_PROVIDERS", "definitely-not-real")
    with pytest.raises(ValueError, match="Unknown intel provider"):
        get_intel_providers()


def test_whitespace_and_case_normalised(monkeypatch):
    # The factory imports concrete provider modules lazily; this test only
    # asserts that case+whitespace normalization doesn't trip the lookup.
    # We use an unknown name (which would also be unknown if not lowercased)
    # to exercise the path without requiring provider impls to exist yet.
    monkeypatch.setenv("DECNET_INTEL_PROVIDERS", "  Mystery , ")
    with pytest.raises(ValueError, match="mystery"):
        get_intel_providers()
