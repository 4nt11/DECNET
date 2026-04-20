"""Pre-deploy validator for MazeNET topologies.

Consumes a hydrated dict (output of
:func:`decnet.topology.persistence.hydrate`) and returns a list of
:class:`ValidationIssue` records.  The deployer calls :func:`validate`
before transitioning to ``DEPLOYING`` and refuses to proceed if any
issue has ``severity=="error"``.

Rules are independent functions so the web editor can surface them as
inline diagnostics without running the full list.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Callable, Literal

from decnet.fleet import all_service_names

Severity = Literal["error", "warning"]


@dataclass
class ValidationIssue:
    severity: Severity
    code: str
    message: str
    target: dict = field(default_factory=dict)


class ValidationError(Exception):
    """Raised by the deployer when a topology fails pre-deploy checks."""

    def __init__(self, issues: list[ValidationIssue]) -> None:
        self.issues = issues
        errors = [i for i in issues if i.severity == "error"]
        super().__init__(
            f"{len(errors)} topology validation error(s): "
            + "; ".join(f"[{i.code}] {i.message}" for i in errors)
        )


# --------------------------------------------------------------------- rules


def check_exactly_one_dmz(h: dict[str, Any]) -> list[ValidationIssue]:
    dmzs = [lan for lan in h["lans"] if lan.get("is_dmz")]
    if len(dmzs) == 1:
        return []
    if not dmzs:
        return [
            ValidationIssue("error", "DMZ_MISSING", "no LAN is marked is_dmz=True")
        ]
    return [
        ValidationIssue(
            "error",
            "DMZ_MULTIPLE",
            f"{len(dmzs)} LANs marked is_dmz=True; exactly one allowed",
            target={"lans": [lan["name"] for lan in dmzs]},
        )
    ]


def check_all_lans_connected_to_dmz(
    h: dict[str, Any],
) -> list[ValidationIssue]:
    lans = {lan["id"]: lan for lan in h["lans"]}
    if not lans:
        return []
    dmz = next((lan for lan in h["lans"] if lan.get("is_dmz")), None)
    if dmz is None:
        return []  # covered by check_exactly_one_dmz

    # Adjacency: LANs share an edge if ≥1 bridge decky is attached to both.
    decky_lans: dict[str, set[str]] = {}
    for edge in h["edges"]:
        decky_lans.setdefault(edge["decky_uuid"], set()).add(edge["lan_id"])

    adj: dict[str, set[str]] = {lid: set() for lid in lans}
    for lan_ids in decky_lans.values():
        if len(lan_ids) < 2:
            continue
        for a in lan_ids:
            for b in lan_ids:
                if a != b:
                    adj[a].add(b)

    reachable = {dmz["id"]}
    frontier = [dmz["id"]]
    while frontier:
        nxt: list[str] = []
        for lid in frontier:
            for peer in adj[lid]:
                if peer not in reachable:
                    reachable.add(peer)
                    nxt.append(peer)
        frontier = nxt

    orphans = [lans[lid]["name"] for lid in lans if lid not in reachable]
    if not orphans:
        return []
    return [
        ValidationIssue(
            "error",
            "DMZ_ORPHAN",
            f"LAN(s) have no bridge path to the DMZ: {', '.join(orphans)}",
            target={"lans": orphans},
        )
    ]


def check_no_orphan_deckies(h: dict[str, Any]) -> list[ValidationIssue]:
    attached: set[str] = {e["decky_uuid"] for e in h["edges"]}
    issues: list[ValidationIssue] = []
    for d in h["deckies"]:
        if d["uuid"] not in attached:
            issues.append(
                ValidationIssue(
                    "error",
                    "DECKY_ORPHAN",
                    f"decky {d['name']!r} has no LAN edges",
                    target={"decky": d["name"]},
                )
            )
    return issues


def check_names_unique(h: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    seen_lan: set[str] = set()
    for lan in h["lans"]:
        if lan["name"] in seen_lan:
            issues.append(
                ValidationIssue(
                    "error",
                    "LAN_NAME_DUP",
                    f"duplicate LAN name {lan['name']!r}",
                    target={"lan": lan["name"]},
                )
            )
        seen_lan.add(lan["name"])
    seen_decky: set[str] = set()
    for d in h["deckies"]:
        if d["name"] in seen_decky:
            issues.append(
                ValidationIssue(
                    "error",
                    "DECKY_NAME_DUP",
                    f"duplicate decky name {d['name']!r}",
                    target={"decky": d["name"]},
                )
            )
        seen_decky.add(d["name"])
    return issues


def check_no_ip_collisions(h: dict[str, Any]) -> list[ValidationIssue]:
    lans_by_name = {lan["name"]: lan for lan in h["lans"]}
    per_lan_ips: dict[str, dict[str, str]] = {}  # lan_name → {ip: decky_name}
    issues: list[ValidationIssue] = []
    for d in h["deckies"]:
        ips_by_lan: dict[str, str] = (d.get("decky_config") or {}).get(
            "ips_by_lan", {}
        )
        for lan_name, ip in ips_by_lan.items():
            lan = lans_by_name.get(lan_name)
            if lan is None:
                issues.append(
                    ValidationIssue(
                        "error",
                        "IP_UNKNOWN_LAN",
                        f"decky {d['name']!r} claims IP in unknown LAN "
                        f"{lan_name!r}",
                        target={"decky": d["name"], "lan": lan_name},
                    )
                )
                continue
            # Out-of-subnet check.
            try:
                if IPv4Address(ip) not in IPv4Network(lan["subnet"]):
                    issues.append(
                        ValidationIssue(
                            "error",
                            "IP_OUT_OF_SUBNET",
                            f"{ip} not inside {lan['subnet']} "
                            f"(decky {d['name']!r}, LAN {lan_name!r})",
                            target={"decky": d["name"], "lan": lan_name, "ip": ip},
                        )
                    )
            except (ValueError, TypeError):
                issues.append(
                    ValidationIssue(
                        "error",
                        "IP_MALFORMED",
                        f"decky {d['name']!r}: malformed IP {ip!r}",
                        target={"decky": d["name"], "ip": ip},
                    )
                )
                continue
            bucket = per_lan_ips.setdefault(lan_name, {})
            if ip in bucket:
                issues.append(
                    ValidationIssue(
                        "error",
                        "IP_COLLISION",
                        f"IP {ip} claimed by both {bucket[ip]!r} and "
                        f"{d['name']!r} in LAN {lan_name!r}",
                        target={
                            "lan": lan_name,
                            "ip": ip,
                            "deckies": [bucket[ip], d["name"]],
                        },
                    )
                )
            else:
                bucket[ip] = d["name"]
    return issues


def check_no_subnet_overlap(h: dict[str, Any]) -> list[ValidationIssue]:
    nets: list[tuple[str, IPv4Network]] = []
    issues: list[ValidationIssue] = []
    for lan in h["lans"]:
        try:
            nets.append((lan["name"], IPv4Network(lan["subnet"])))
        except ValueError:
            issues.append(
                ValidationIssue(
                    "error",
                    "SUBNET_MALFORMED",
                    f"LAN {lan['name']!r}: malformed subnet {lan['subnet']!r}",
                    target={"lan": lan["name"]},
                )
            )
    for i, (na, a) in enumerate(nets):
        for nb, b in nets[i + 1 :]:
            if a.overlaps(b):
                issues.append(
                    ValidationIssue(
                        "error",
                        "SUBNET_OVERLAP",
                        f"LAN {na!r} ({a}) overlaps LAN {nb!r} ({b})",
                        target={"lans": [na, nb]},
                    )
                )
    return issues


def check_services_known(h: dict[str, Any]) -> list[ValidationIssue]:
    known = set(all_service_names())
    issues: list[ValidationIssue] = []
    for d in h["deckies"]:
        for svc in d.get("services", []):
            if svc not in known:
                issues.append(
                    ValidationIssue(
                        "error",
                        "UNKNOWN_SERVICE",
                        f"decky {d['name']!r}: unknown service {svc!r}",
                        target={"decky": d["name"], "service": svc},
                    )
                )
    return issues


def check_service_config_shape(h: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for d in h["deckies"]:
        svc_cfg = (d.get("decky_config") or {}).get("service_config") or {}
        declared = set(d.get("services", []))
        for svc_name in svc_cfg:
            if svc_name not in declared:
                issues.append(
                    ValidationIssue(
                        "error",
                        "SERVICE_CFG_UNDECLARED",
                        f"decky {d['name']!r}: service_config for "
                        f"{svc_name!r} but service not in services list",
                        target={"decky": d["name"], "service": svc_name},
                    )
                )
    return issues


_RULES: list[Callable[[dict[str, Any]], list[ValidationIssue]]] = [
    check_exactly_one_dmz,
    check_all_lans_connected_to_dmz,
    check_no_orphan_deckies,
    check_names_unique,
    check_no_ip_collisions,
    check_no_subnet_overlap,
    check_services_known,
    check_service_config_shape,
]


def validate(hydrated: dict[str, Any]) -> list[ValidationIssue]:
    """Run every rule and return the flat list of issues (may be empty)."""
    out: list[ValidationIssue] = []
    for rule in _RULES:
        out.extend(rule(hydrated))
    return out


def errors(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    return [i for i in issues if i.severity == "error"]
