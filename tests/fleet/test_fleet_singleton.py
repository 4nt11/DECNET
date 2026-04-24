"""
Tests for fleet_singleton service behavior.

Verifies that:
  - The sniffer is registered but marked as fleet_singleton
  - fleet_singleton services are excluded from compose generation
  - fleet_singleton services are excluded from random service assignment
"""

from decnet.composer import generate_compose
from decnet.fleet import all_service_names, build_deckies
from decnet.models import DeckyConfig, DecnetConfig
from decnet.services.registry import all_services, get_service


def test_sniffer_is_fleet_singleton():
    svc = get_service("sniffer")
    assert svc.fleet_singleton is True


def test_non_sniffer_services_are_not_fleet_singleton():
    for name, svc in all_services().items():
        if name == "sniffer":
            continue
        assert svc.fleet_singleton is False, f"{name} should not be fleet_singleton"


def test_sniffer_excluded_from_all_service_names():
    names = all_service_names()
    assert "sniffer" not in names


def test_sniffer_still_in_registry():
    """Sniffer must remain discoverable in the registry even though it's a singleton."""
    registry = all_services()
    assert "sniffer" in registry


def test_compose_skips_fleet_singleton():
    """When a decky lists 'sniffer' in its services, compose must not generate a container."""
    config = DecnetConfig(
        mode="unihost",
        interface="eth0",
        subnet="192.168.1.0/24",
        gateway="192.168.1.1",
        host_ip="192.168.1.5",
        deckies=[
            DeckyConfig(
                name="decky-01",
                ip="192.168.1.10",
                services=["ssh", "sniffer"],
                distro="debian",
                base_image="debian:bookworm-slim",
                hostname="test-host",
            ),
        ],
    )
    compose = generate_compose(config)
    services = compose["services"]

    assert "decky-01" in services  # base container exists
    assert "decky-01-ssh" in services  # ssh service exists
    assert "decky-01-sniffer" not in services  # sniffer skipped


def test_randomize_never_picks_sniffer():
    """Random service assignment must never include fleet_singleton services."""
    all_drawn: set[str] = set()
    for _ in range(100):
        deckies = build_deckies(
            n=1,
            ips=["10.0.0.10"],
            services_explicit=None,
            randomize_services=True,
        )
        all_drawn.update(deckies[0].services)

    assert "sniffer" not in all_drawn
