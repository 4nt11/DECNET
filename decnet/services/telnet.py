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
            # NODE_NAME is the authoritative decky identifier for log
            # attribution — matches the host path used for the artifacts
            # bind mount below.
            "NODE_NAME": decky_name,
        }
        if "hostname" in cfg:
            env["TELNET_HOSTNAME"] = cfg["hostname"]

        # Quarantine mount symmetric to the SSH service — sessrec appends
        # pty transcripts to /var/lib/systemd/coredump/transcripts/ inside
        # the container, which the host sees under artifacts/<decky>/telnet/.
        quarantine_host = f"/var/lib/decnet/artifacts/{decky_name}/telnet"
        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-telnet",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
            "volumes": [f"{quarantine_host}:/var/lib/systemd/coredump:rw"],
        }

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
