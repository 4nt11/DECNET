from pathlib import Path

from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "telnet"


class TelnetService(BaseService):
    """
    Real telnetd using busybox telnetd + rsyslog logging pipeline.

    Replaced Cowrie emulation (which also started an SSH daemon on port 22)
    with a real busybox telnetd so only port 23 is exposed and auth events
    are logged as RFC 5424 via the same rsyslog bridge used by the SSH service.

    service_cfg keys:
        password    Root password (default: "admin")
        hostname    Override container hostname
    """

    name = "telnet"
    ports = [23]
    default_image = "build"

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        env: dict = {
            "TELNET_ROOT_PASSWORD": cfg.get("password", "admin"),
        }
        if "hostname" in cfg:
            env["TELNET_HOSTNAME"] = cfg["hostname"]

        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-telnet",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
        }

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
