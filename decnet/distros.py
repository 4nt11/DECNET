# SPDX-License-Identifier: AGPL-3.0-or-later
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


# Base images are pinned by digest (sha256) to make `docker pull`
# reproducible — a registry-side rebuild of "debian:bookworm-slim"
# can't silently swap content under us.  The :tag is kept for human
# readability; the @sha256 is what Docker actually resolves.
# Refresh procedure: `docker pull <tag>` then `docker inspect
# --format '{{index .RepoDigests 0}}' <tag>`.  Last refreshed 2026-05-03.
_DEBIAN_BOOKWORM = "debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252"
_UBUNTU_22_04    = "ubuntu:22.04@sha256:962f6cadeae0ea6284001009daa4cc9a8c37e75d1f5191cf0eb83fe565b63dd7"
_UBUNTU_20_04    = "ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214"
_ROCKY_9         = "rockylinux:9-minimal@sha256:305de618a5681ff75b1d608fd22b10f362867dff2f550a4f1d427d21cd7f42b4"
_CENTOS_7        = "centos:7@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4"
_ALPINE_3_19     = "alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
_FEDORA_39       = "fedora:39@sha256:d63d63fe593749a5e8dbc8152427d40bbe0ece53d884e00e5f3b44859efa5077"
_KALI_ROLLING    = "kalilinux/kali-rolling@sha256:1fd0364490011f245688c6ed9fee498a11cd779badfbb0b1d3a721d0f49f2d15"
_ARCH_LATEST     = "archlinux:latest@sha256:5ba8bb318666baef4d33afefc0e65db80f38b23503cb8e7b150d315cc2d4d5da"


DISTROS: dict[str, DistroProfile] = {
    "debian": DistroProfile(
        slug="debian",
        image=_DEBIAN_BOOKWORM,
        display_name="Debian 12 (Bookworm)",
        hostname_style="generic",
        build_base=_DEBIAN_BOOKWORM,
    ),
    "ubuntu22": DistroProfile(
        slug="ubuntu22",
        image=_UBUNTU_22_04,
        display_name="Ubuntu 22.04 LTS (Jammy)",
        hostname_style="generic",
        build_base=_UBUNTU_22_04,
    ),
    "ubuntu20": DistroProfile(
        slug="ubuntu20",
        image=_UBUNTU_20_04,
        display_name="Ubuntu 20.04 LTS (Focal)",
        hostname_style="generic",
        build_base=_UBUNTU_20_04,
    ),
    "rocky9": DistroProfile(
        slug="rocky9",
        image=_ROCKY_9,
        display_name="Rocky Linux 9",
        hostname_style="rhel",
        build_base=_DEBIAN_BOOKWORM,  # Dockerfiles use apt-get; fall back to debian
    ),
    "centos7": DistroProfile(
        slug="centos7",
        image=_CENTOS_7,
        display_name="CentOS 7",
        hostname_style="rhel",
        build_base=_DEBIAN_BOOKWORM,  # Dockerfiles use apt-get; fall back to debian
    ),
    "alpine": DistroProfile(
        slug="alpine",
        image=_ALPINE_3_19,
        display_name="Alpine Linux 3.19",
        hostname_style="minimal",
        build_base=_DEBIAN_BOOKWORM,  # Dockerfiles use apt-get; fall back to debian
    ),
    "fedora": DistroProfile(
        slug="fedora",
        image=_FEDORA_39,
        display_name="Fedora 39",
        hostname_style="rhel",
        build_base=_DEBIAN_BOOKWORM,  # Dockerfiles use apt-get; fall back to debian
    ),
    "kali": DistroProfile(
        slug="kali",
        image=_KALI_ROLLING,
        display_name="Kali Linux (Rolling)",
        hostname_style="rolling",
        build_base=_KALI_ROLLING,  # Debian-based, apt-get compatible
    ),
    "arch": DistroProfile(
        slug="arch",
        image=_ARCH_LATEST,
        display_name="Arch Linux",
        hostname_style="rolling",
        build_base=_DEBIAN_BOOKWORM,  # Dockerfiles use apt-get; fall back to debian
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
    word = random.choice(_NAME_WORDS)  # nosec B311
    num = random.randint(10, 99)  # nosec B311

    if style == "rhel":
        # RHEL/CentOS/Fedora convention: word+num.localdomain
        return f"{word}{num}.localdomain"
    elif style == "minimal":
        return f"{word}-{num}"
    elif style == "rolling":
        # Kali/Arch: just a word, no suffix
        return f"{word}-{random.choice(_NAME_WORDS)}"  # nosec B311
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
    return random.choice(list(DISTROS.values()))  # nosec B311


def all_distros() -> dict[str, DistroProfile]:
    return dict(DISTROS)
