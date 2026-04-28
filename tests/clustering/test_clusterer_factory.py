"""Tests for :mod:`decnet.clustering.factory`."""
from __future__ import annotations

import pytest

from decnet.clustering.base import Clusterer
from decnet.clustering.factory import get_clusterer
from decnet.clustering.impl.connected_components import ConnectedComponentsClusterer


def test_default_returns_connected_components(monkeypatch):
    monkeypatch.delenv("DECNET_CLUSTERER_TYPE", raising=False)
    c = get_clusterer()
    assert isinstance(c, ConnectedComponentsClusterer)
    assert isinstance(c, Clusterer)
    assert c.name == "connected_components"


def test_explicit_connected_components(monkeypatch):
    monkeypatch.setenv("DECNET_CLUSTERER_TYPE", "connected_components")
    c = get_clusterer()
    assert isinstance(c, ConnectedComponentsClusterer)


def test_unknown_clusterer_type_raises(monkeypatch):
    monkeypatch.setenv("DECNET_CLUSTERER_TYPE", "nope")
    with pytest.raises(ValueError, match="Unknown clusterer"):
        get_clusterer()


def test_case_insensitive(monkeypatch):
    monkeypatch.setenv("DECNET_CLUSTERER_TYPE", "  CONNECTED_COMPONENTS  ")
    c = get_clusterer()
    assert isinstance(c, ConnectedComponentsClusterer)
