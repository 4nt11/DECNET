"""ATT&CK technique-id → display-name catalogue.

Pinned to the same ATT&CK release the rule engine emits on
(``v15.1`` per ``decnet/ttp/impl/rule_engine.py:_ATTACK_RELEASE``). The
operator UI uses these names to render "T1595 — Active Scanning"
instead of just "T1595" in the TTPs-observed rollup and the per-tag
inspector. Names are the canonical MITRE labels, not author-supplied
strings on rules — keeping them here means a rule author can't typo a
technique name and the entire fleet sees the typo.

Bumping ``_ATTACK_RELEASE`` requires reviewing this file: any
techniques that were renamed need their entries updated in the same
commit. See TTP_TAGGING.md §"Hard parts §8 ATT&CK matrix drift".

Coverage policy: every technique_id / sub_technique_id appearing in
``rules/ttp/`` MUST have an entry here. The
``tests/ttp/test_attack_catalog.py`` coverage test enforces this so a
rule author who adds a new technique gets a loud failure rather than
a silent UI fallback.
"""
from __future__ import annotations

from typing import Final

# Top-level techniques + sub-techniques referenced by `rules/ttp/`
# (R0001..R0058). Names from MITRE ATT&CK Enterprise v15.1.
TECHNIQUE_NAMES: Final[dict[str, str]] = {
    # ── Top-level techniques ─────────────────────────────────────────
    "T1003": "OS Credential Dumping",
    "T1016": "System Network Configuration Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1029": "Scheduled Transfer",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1046": "Network Service Discovery",
    "T1049": "System Network Connections Discovery",
    "T1053": "Scheduled Task/Job",
    "T1059": "Command and Scripting Interpreter",
    "T1070": "Indicator Removal",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1090": "Proxy",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1135": "Network Share Discovery",
    "T1136": "Create Account",
    "T1190": "Exploit Public-Facing Application",
    "T1204": "User Execution",
    "T1213": "Data from Information Repositories",
    "T1482": "Domain Trust Discovery",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1496": "Resource Hijacking",
    "T1505": "Server Software Component",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1557": "Adversary-in-the-Middle",
    "T1566": "Phishing",
    "T1567": "Exfiltration Over Web Service",
    "T1586": "Compromise Accounts",
    "T1588": "Obtain Capabilities",
    "T1595": "Active Scanning",
    "T1602": "Data from Configuration Repository",
    "T1611": "Escape to Host",
    # ── Sub-techniques ───────────────────────────────────────────────
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.003": "Application Layer Protocol: Mail Protocols",
    "T1078.001": "Valid Accounts: Default Accounts",
    "T1087.002": "Account Discovery: Domain Account",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1136.001": "Create Account: Local Account",
    "T1204.002": "User Execution: Malicious File",
    "T1505.003": "Server Software Component: Web Shell",
    "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.007": "Unsecured Credentials: Container API",
    "T1557.001": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1566.003": "Phishing: Spearphishing via Service",
    "T1586.002": "Compromise Accounts: Email Accounts",
    "T1588.001": "Obtain Capabilities: Malware",
    "T1588.002": "Obtain Capabilities: Tool",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1602.002": "Data from Configuration Repository: Network Device Configuration Dump",
}


def technique_name(technique_id: str | None) -> str | None:
    """Return the canonical ATT&CK display name for *technique_id*.

    ``None`` for unknown IDs — the UI falls back to showing the bare
    ID. Adding a rule that emits an unknown technique should be a
    deploy-time loud failure (see ``tests/ttp/test_attack_catalog.py``)
    rather than a silent UI fallback in production.
    """
    if not technique_id:
        return None
    return TECHNIQUE_NAMES.get(technique_id)


__all__ = ["TECHNIQUE_NAMES", "technique_name"]
