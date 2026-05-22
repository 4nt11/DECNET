from pathlib import Path
from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "dns"

_DEFAULT_VERSION = "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.10"


class DNSService(BaseService):
    name = "dns"
    ports = [53]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="zone_mode",
            label="Zone mode",
            type="enum",
            enum=["auth", "recursive", "open"],
            default="auth",
            help="auth: authoritative only; recursive: forwards out-of-zone queries upstream (real_recursive=true) or sinkholes them; open: responds to everything (amp bait)",
        ),
        ServiceConfigField(
            key="domain",
            label="Domain",
            type="string",
            default="",
            placeholder="corp.local",
            help="Authoritative zone name. Leave empty to generate a plausible domain from the decky name.",
        ),
        ServiceConfigField(
            key="bind_version",
            label="BIND version banner",
            type="string",
            default=_DEFAULT_VERSION,
            help="Returned for version.bind CHAOS TXT queries.",
        ),
        ServiceConfigField(
            key="nsid",
            label="NSID",
            type="string",
            default="",
            help="EDNS NSID string. Leave empty to derive from decky identity.",
        ),
        ServiceConfigField(
            key="extra_records",
            label="Extra records",
            type="textarea",
            default="",
            placeholder="www A 10.0.0.5\nmail TXT v=spf1 ~all",
            help="Additional zone records, one per line: <name> <TYPE> <value>",
        ),
        ServiceConfigField(
            key="real_recursive",
            label="Real recursive forwarding",
            type="bool",
            default=False,
            help="When zone_mode=recursive, forward out-of-zone queries to an upstream resolver instead of returning a sinkhole. Falls back to sinkhole on upstream timeout.",
        ),
        ServiceConfigField(
            key="upstream",
            label="Upstream resolver",
            type="string",
            default="8.8.8.8:53",
            placeholder="8.8.8.8:53",
            help="Upstream DNS resolver used when real_recursive is enabled (host:port).",
        ),
        ServiceConfigField(
            key="forward_budget",
            label="Forward budget (queries/window)",
            type="string",
            default="50",
            help="Maximum upstream forwarding calls allowed within the rate window. Excess queries fall back to sinkhole.",
        ),
        ServiceConfigField(
            key="forward_window",
            label="Forward budget window (seconds)",
            type="string",
            default="1.0",
            help="Rolling window in seconds for the forward budget counter.",
        ),
    ]

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        env: dict[str, str] = {
            "NODE_NAME": decky_name,
            "DNS_ZONE_MODE":    str(cfg.get("zone_mode",    "auth")),
            "DNS_DOMAIN":       str(cfg.get("domain",       "")),
            "DNS_BIND_VERSION": str(cfg.get("bind_version", _DEFAULT_VERSION)),
            "DNS_NSID":         str(cfg.get("nsid",         "")),
            "DNS_EXTRA_RECORDS":    str(cfg.get("extra_records",    "")),
            "DNS_REAL_RECURSIVE":   "true" if cfg.get("real_recursive") else "false",
            "DNS_UPSTREAM":         str(cfg.get("upstream",        "8.8.8.8:53")),
            "DNS_FORWARD_BUDGET":   str(cfg.get("forward_budget",  "50")),
            "DNS_FORWARD_WINDOW":   str(cfg.get("forward_window",  "1.0")),
        }
        if log_target:
            env["LOG_TARGET"] = log_target
        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-dns",
            "restart": "unless-stopped",
            "environment": env,
        }

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR

    def udp_ports(self, cfg: dict | None = None) -> list[int]:
        return [53]
