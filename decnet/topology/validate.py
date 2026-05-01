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
from decnet.logging import get_logger
from decnet.services.registry import get_service

log = get_logger("topology.validate")

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


def check_gateway_homed_in_dmz(h: dict[str, Any]) -> list[ValidationIssue]:
    """Gateway deckies must live in a DMZ LAN.

    ``forwards_l3=True`` triggers host-port publishing in the compose
    generator (see :mod:`decnet.topology.compose`); a gateway sitting
    on an internal LAN would publish ports on the host without anyone
    on the right side of the perimeter able to reach the service
    legitimately.  The semantic is "this decky is the front door" —
    only meaningful when the LAN is the DMZ.

    Not in ``_RULES``: ``forwards_l3`` encodes two semantics — internal
    bridge routing (generator-assigned, legitimately on non-DMZ LANs) and
    DMZ gateway publication (operator-assigned, must be DMZ-homed).
    Standing validation cannot distinguish them; this check is therefore
    path-specific and called only on the explicit operator flip path
    (``forwards_l3: False → True`` via ``apply_update_decky``).
    """
    if not h.get("deckies"):
        return []

    lans_by_id = {lan["id"]: lan for lan in h["lans"]}
    dmz_lan_ids = {
        lan["id"] for lan in h["lans"] if lan.get("is_dmz")
    }
    dmz_lan_names = {
        lan["name"] for lan in h["lans"] if lan.get("is_dmz")
    }

    # Home-LAN selection mirrors the frontend hydration: prefer the
    # non-bridge edge.  Falls back to the first edge if no
    # is_bridge flag is set (legacy rows).
    home_lan_for: dict[str, str] = {}  # decky_uuid → lan_id
    for e in h["edges"]:
        if e.get("is_bridge") is False and e["decky_uuid"] not in home_lan_for:
            home_lan_for[e["decky_uuid"]] = e["lan_id"]
    for e in h["edges"]:
        if e["decky_uuid"] in home_lan_for:
            continue
        home_lan_for[e["decky_uuid"]] = e["lan_id"]

    issues: list[ValidationIssue] = []
    for d in h["deckies"]:
        cfg = d.get("decky_config") or {}
        if not cfg.get("forwards_l3"):
            continue
        home_lan_id = home_lan_for.get(d["uuid"])
        if home_lan_id is None or home_lan_id not in dmz_lan_ids:
            home_lan_name = (
                lans_by_id.get(home_lan_id, {}).get("name")
                if home_lan_id
                else "(no home LAN)"
            )
            allowed = ", ".join(sorted(dmz_lan_names)) or "(no DMZ defined)"
            issues.append(
                ValidationIssue(
                    "error",
                    "GATEWAY_NOT_IN_DMZ",
                    f"gateway decky {d['name']!r} is on LAN "
                    f"{home_lan_name!r}; gateways must home in a DMZ "
                    f"LAN ({allowed})",
                    target={"decky": d["name"], "lan": home_lan_name},
                )
            )
    return issues


def check_no_host_port_collision(h: dict[str, Any]) -> list[ValidationIssue]:
    """Flag gateway service ports that are already bound on the host.

    Only gateway deckies (``forwards_l3=True`` in decky_config) publish
    ports (see decnet/topology/compose.py).  Best-effort: if ``psutil``
    isn't importable or probing fails, returns no issues.
    """
    wanted: dict[int, str] = {}  # host_port → gateway decky name
    for d in h["deckies"]:
        cfg = d.get("decky_config") or {}
        if not cfg.get("forwards_l3"):
            continue
        for svc_name in d.get("services", []):
            svc = get_service(svc_name)
            if svc is None or getattr(svc, "fleet_singleton", False):
                continue
            for port in getattr(svc, "ports", []) or []:
                wanted.setdefault(int(port), d["name"])
    if not wanted:
        return []

    try:
        import psutil
        bound = {
            c.laddr.port
            for c in psutil.net_connections(kind="inet")
            if c.status == psutil.CONN_LISTEN and c.laddr
        }
    except ImportError:
        log.warning("psutil not available; skipping host port collision check")
        return []

    issues: list[ValidationIssue] = []
    for port, decky_name in wanted.items():
        if port in bound:
            issues.append(
                ValidationIssue(
                    "warning",
                    "PORT_COLLISION",
                    f"host port {port} is already bound; "
                    f"gateway {decky_name!r} may fail to publish it",
                    target={"decky": decky_name, "port": port},
                )
            )
    return issues


# Pure-data rules.  Host-state rules (like PORT_COLLISION) are
# *not* listed here — they're called separately by the live deployer
# so that unit tests exercising validate() stay hermetic.
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
# check_gateway_homed_in_dmz is intentionally absent — it is path-specific
# (forwards_l3 overloads two semantics). See its docstring.


def validate(hydrated: dict[str, Any]) -> list[ValidationIssue]:
    """Run every rule and return the flat list of issues (may be empty)."""
    out: list[ValidationIssue] = []
    for rule in _RULES:
        out.extend(rule(hydrated))
    return out


def errors(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    return [i for i in issues if i.severity == "error"]
