"""
Machine archetype profiles for DECNET deckies.

An archetype is a pre-packaged identity: a realistic combination of services
and OS choices that makes a decky look like a specific class of machine
(workstation, printer, database server, etc.) without the user needing to
know which services or distros to pick.

Usage in INI config:
    [my-workstations]
    archetype=windows-workstation
    amount=4

Usage via CLI:
    decnet deploy --deckies 3 --archetype linux-server
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Archetype:
    slug: str
    display_name: str
    description: str
    services: list[str]           # default service set for this machine type
    preferred_distros: list[str]  # distro slugs to rotate through
    nmap_os: str = "linux"        # OS family slug for TCP/IP stack spoofing (see os_fingerprint.py)


ARCHETYPES: dict[str, Archetype] = {
    "windows-workstation": Archetype(
        slug="windows-workstation",
        display_name="Windows Workstation",
        description="Corporate Windows desktop: SMB shares + RDP access",
        services=["smb", "rdp"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="windows",
    ),
    "windows-server": Archetype(
        slug="windows-server",
        display_name="Windows Server",
        description="Windows domain member: SMB, RDP, and LDAP directory",
        services=["smb", "rdp", "ldap"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="windows",
    ),
    "domain-controller": Archetype(
        slug="domain-controller",
        display_name="Domain Controller",
        description="Active Directory DC: LDAP, SMB, RDP, LLMNR",
        services=["ldap", "smb", "rdp", "llmnr"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="windows",
    ),
    "linux-server": Archetype(
        slug="linux-server",
        display_name="Linux Server",
        description="General-purpose Linux host: SSH + HTTP",
        services=["ssh", "http"],
        preferred_distros=["debian", "ubuntu22", "rocky9", "fedora"],
        nmap_os="linux",
    ),
    "web-server": Archetype(
        slug="web-server",
        display_name="Web Server",
        description="Public-facing web host: HTTP + FTP",
        services=["http", "ftp"],
        preferred_distros=["debian", "ubuntu22", "ubuntu20"],
        nmap_os="linux",
    ),
    "database-server": Archetype(
        slug="database-server",
        display_name="Database Server",
        description="Data tier host: MySQL, PostgreSQL, Redis",
        services=["mysql", "postgres", "redis"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="linux",
    ),
    "mail-server": Archetype(
        slug="mail-server",
        display_name="Mail Server",
        description="SMTP/IMAP/POP3 mail relay",
        services=["smtp", "pop3", "imap"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="linux",
    ),
    "file-server": Archetype(
        slug="file-server",
        display_name="File Server",
        description="SMB/FTP/SFTP file storage node",
        services=["smb", "ftp", "ssh"],
        preferred_distros=["debian", "ubuntu22", "rocky9"],
        nmap_os="linux",
    ),
    "printer": Archetype(
        slug="printer",
        display_name="Network Printer",
        description="Network-attached printer: SNMP + FTP",
        services=["snmp", "ftp"],
        preferred_distros=["alpine", "debian"],
        nmap_os="embedded",
    ),
    "iot-device": Archetype(
        slug="iot-device",
        display_name="IoT Device",
        description="Embedded/IoT device: MQTT, SNMP, Telnet",
        services=["mqtt", "snmp", "telnet"],
        preferred_distros=["alpine"],
        nmap_os="embedded",
    ),
    "industrial-control": Archetype(
        slug="industrial-control",
        display_name="Industrial Control System",
        description="ICS/SCADA node: Conpot (Modbus/S7/DNP3) + SNMP",
        services=["conpot", "snmp"],
        preferred_distros=["debian"],
        nmap_os="embedded",
    ),
    "voip-server": Archetype(
        slug="voip-server",
        display_name="VoIP Server",
        description="SIP PBX / VoIP gateway",
        services=["sip"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="linux",
    ),
    "monitoring-node": Archetype(
        slug="monitoring-node",
        display_name="Monitoring Node",
        description="Infrastructure monitoring host: SNMP + SSH",
        services=["snmp", "ssh"],
        preferred_distros=["debian", "rocky9"],
        nmap_os="linux",
    ),
    "devops-host": Archetype(
        slug="devops-host",
        display_name="DevOps Host",
        description="CI/CD or container host: Docker API + SSH + K8s",
        services=["docker_api", "ssh", "k8s"],
        preferred_distros=["ubuntu22", "debian"],
        nmap_os="linux",
    ),
    "deaddeck": Archetype(
        slug="deaddeck",
        display_name="Deaddeck (Entry Point)",
        description="Internet-facing entry point with real interactive SSH — no honeypot emulation",
        services=["real_ssh"],
        preferred_distros=["debian", "ubuntu22"],
        nmap_os="linux",
    ),
}


def get_archetype(slug: str) -> Archetype:
    if slug not in ARCHETYPES:
        available = ", ".join(sorted(ARCHETYPES))
        raise ValueError(f"Unknown archetype '{slug}'. Available: {available}")
    return ARCHETYPES[slug]


def all_archetypes() -> dict[str, Archetype]:
    return dict(ARCHETYPES)


def random_archetype() -> Archetype:
    return random.choice(list(ARCHETYPES.values()))
