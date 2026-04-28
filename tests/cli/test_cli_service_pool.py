"""
Tests for the CLI service pool — verifies that --randomize-services draws
from all registered services, not just the original hardcoded 5.
"""

from decnet.fleet import all_service_names as _all_service_names, build_deckies as _build_deckies
from decnet.services.registry import all_services


ORIGINAL_5 = {"ssh", "smb", "rdp", "http", "ftp"}


def test_all_service_names_covers_per_decky_services():
    """_all_service_names() must return every per-decky service (not fleet singletons)."""
    pool = set(_all_service_names())
    registry = all_services()
    per_decky = {name for name, svc in registry.items() if not svc.fleet_singleton}
    assert pool == per_decky


def test_all_service_names_is_sorted():
    names = _all_service_names()
    assert names == sorted(names)


def test_all_service_names_includes_at_least_25():
    assert len(_all_service_names()) >= 25


def test_all_service_names_includes_all_original_5():
    pool = set(_all_service_names())
    assert ORIGINAL_5.issubset(pool)


def test_randomize_services_pool_exceeds_original_5():
    """
    After enough random draws, at least one service outside the original 5 must appear.
    With 25 services and picking 1-3 at a time, 200 draws makes this ~100% certain.
    """
    all_drawn: set[str] = set()
    for _ in range(200):
        deckies = _build_deckies(
            n=1,
            ips=["10.0.0.10"],
            services_explicit=None,
            randomize_services=True,
        )
        all_drawn.update(deckies[0].services)

    beyond_original = all_drawn - ORIGINAL_5
    assert beyond_original, (
        f"After 200 draws only saw the original 5 services. "
        f"All drawn: {sorted(all_drawn)}"
    )


def test_build_deckies_randomize_services_valid():
    """All randomly chosen services must exist in the registry."""
    registry = set(all_services().keys())
    for _ in range(50):
        deckies = _build_deckies(
            n=3,
            ips=["10.0.0.10", "10.0.0.11", "10.0.0.12"],
            services_explicit=None,
            randomize_services=True,
        )
        for decky in deckies:
            unknown = set(decky.services) - registry
            assert not unknown, f"Decky {decky.name} got unknown services: {unknown}"


def test_build_deckies_explicit_services_unchanged():
    """Explicit service list must pass through untouched."""
    deckies = _build_deckies(
        n=2,
        ips=["10.0.0.10", "10.0.0.11"],
        services_explicit=["ssh", "ftp"],
        randomize_services=False,
    )
    for decky in deckies:
        assert decky.services == ["ssh", "ftp"]
