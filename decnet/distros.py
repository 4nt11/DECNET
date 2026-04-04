"""
Distro profiles for DECNET deckies.

Each profile maps a human-readable slug to a Docker image and OS metadata used
to make deckies look like heterogeneous real machines on the LAN.
"""

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class DistroProfile:
    slug: str           # CLI-facing identifier, e.g. "debian", "rocky9"
    image: str          # Docker image tag (used for the base/IP-holder container)
    display_name: str   # Human-readable label shown in tables
    hostname_style: str # "generic" | "rhel" | "minimal" | "rolling"
    build_base: str     # apt-compatible image for service Dockerfiles (FROM ${BASE_IMAGE})


DISTROS: dict[str, DistroProfile] = {
    "debian": DistroProfile(
        slug="debian",
        image="debian:bookworm-slim",
        display_name="Debian 12 (Bookworm)",
        hostname_style="generic",
        build_base="debian:bookworm-slim",
    ),
    "ubuntu22": DistroProfile(
        slug="ubuntu22",
        image="ubuntu:22.04",
        display_name="Ubuntu 22.04 LTS (Jammy)",
        hostname_style="generic",
        build_base="ubuntu:22.04",
    ),
    "ubuntu20": DistroProfile(
        slug="ubuntu20",
        image="ubuntu:20.04",
        display_name="Ubuntu 20.04 LTS (Focal)",
        hostname_style="generic",
        build_base="ubuntu:20.04",
    ),
    "rocky9": DistroProfile(
        slug="rocky9",
        image="rockylinux:9-minimal",
        display_name="Rocky Linux 9",
        hostname_style="rhel",
        build_base="debian:bookworm-slim",  # Dockerfiles use apt-get; fall back to debian
    ),
    "centos7": DistroProfile(
        slug="centos7",
        image="centos:7",
        display_name="CentOS 7",
        hostname_style="rhel",
        build_base="debian:bookworm-slim",  # Dockerfiles use apt-get; fall back to debian
    ),
    "alpine": DistroProfile(
        slug="alpine",
        image="alpine:3.19",
        display_name="Alpine Linux 3.19",
        hostname_style="minimal",
        build_base="debian:bookworm-slim",  # Dockerfiles use apt-get; fall back to debian
    ),
    "fedora": DistroProfile(
        slug="fedora",
        image="fedora:39",
        display_name="Fedora 39",
        hostname_style="rhel",
        build_base="debian:bookworm-slim",  # Dockerfiles use apt-get; fall back to debian
    ),
    "kali": DistroProfile(
        slug="kali",
        image="kalilinux/kali-rolling",
        display_name="Kali Linux (Rolling)",
        hostname_style="rolling",
        build_base="kalilinux/kali-rolling",  # Debian-based, apt-get compatible
    ),
    "arch": DistroProfile(
        slug="arch",
        image="archlinux:latest",
        display_name="Arch Linux",
        hostname_style="rolling",
        build_base="debian:bookworm-slim",  # Dockerfiles use apt-get; fall back to debian
    ),
}

_NAME_WORDS = [
    "alpha", "bravo", "charlie", "delta", "echo",
    "foxtrot", "golf", "hotel", "india", "juliet",
    "kilo", "lima", "mike", "nova", "oscar",
    "prod", "web", "db", "mail", "proxy",
    "dev", "stage", "backup", "monitor", "files",
]


def random_hostname(distro_slug: str = "debian") -> str:
    """Generate a plausible hostname for the given distro style."""
    profile = DISTROS.get(distro_slug)
    style = profile.hostname_style if profile else "generic"
    word = random.choice(_NAME_WORDS)
    num = random.randint(10, 99)

    if style == "rhel":
        # RHEL/CentOS/Fedora convention: word+num.localdomain
        return f"{word}{num}.localdomain"
    elif style == "minimal":
        return f"{word}-{num}"
    elif style == "rolling":
        # Kali/Arch: just a word, no suffix
        return f"{word}-{random.choice(_NAME_WORDS)}"
    else:
        # Debian/Ubuntu: SRV-WORD-nn
        return f"SRV-{word.upper()}-{num}"


def get_distro(slug: str) -> DistroProfile:
    if slug not in DISTROS:
        raise ValueError(
            f"Unknown distro '{slug}'. Available: {', '.join(sorted(DISTROS))}"
        )
    return DISTROS[slug]


def random_distro() -> DistroProfile:
    return random.choice(list(DISTROS.values()))


def all_distros() -> dict[str, DistroProfile]:
    return dict(DISTROS)
