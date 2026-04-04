from abc import ABC, abstractmethod
from pathlib import Path


class BaseService(ABC):
    """
    Contract every honeypot service plugin must implement.

    To add a new service: subclass BaseService in a new file under decnet/services/.
    The registry auto-discovers all subclasses at import time.
    """

    name: str           # unique slug, e.g. "ssh", "smb"
    ports: list[int]    # ports this service listens on inside the container
    default_image: str  # Docker image tag, or "build" if a Dockerfile is needed

    @abstractmethod
    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        """
        Return the docker-compose service dict for this service on a given decky.

        Networking keys (networks, ipv4_address) are injected by the composer —
        do NOT include them here. Include: image/build, environment, volumes,
        restart, and any service-specific options.

        Args:
            decky_name: unique identifier for the decky (e.g. "decky-01")
            log_target: "ip:port" string if log forwarding is enabled, else None
            service_cfg: optional per-service persona config from INI subsection
        """

    def dockerfile_context(self) -> Path | None:
        """
        Return path to the build context directory if this service needs a custom
        image built. Return None if default_image is used directly.
        """
        return None
