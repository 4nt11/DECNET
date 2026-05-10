import base64
import binascii
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

# Sentinel prefix used by the deploy wizard to ship multi-line textarea values
# through ConfigParser without relying on its multi-line continuation syntax.
# Plain raw values without the prefix are accepted as-is so direct API
# submitters (PUT /…/services/{svc}/config) keep working with raw strings.
TEXTAREA_B64_PREFIX = "b64:"

FieldType = Literal["string", "password", "int", "bool", "textarea", "enum", "multi_enum"]


@dataclass(frozen=True)
class ServiceConfigField:
    """
    Declarative descriptor for one user-editable knob on a service.

    The Inspector form (Fleet + MazeNET) renders inputs from this metadata,
    and BaseService.validate_cfg coerces submitted values against it.
    """

    key: str
    label: str
    type: FieldType = "string"
    default: Any = None
    secret: bool = False
    help: str | None = None
    enum: list[str] | None = None
    placeholder: str | None = None

    def to_json(self) -> dict:
        d = asdict(self)
        # Frontend doesn't need a None enum dangling on non-enum fields
        if self.enum is None:
            d.pop("enum", None)
        return d


class ConfigValidationError(ValueError):
    """Raised when a submitted service_cfg value cannot be coerced to its declared type."""


class BaseService(ABC):
    """
    Contract every honeypot service plugin must implement.

    To add a new service: subclass BaseService in a new file under decnet/services/.
    The registry auto-discovers all subclasses at import time.
    """

    name: str           # unique slug, e.g. "ssh", "smb"
    ports: list[int]    # ports this service listens on inside the container
    default_image: str  # Docker image tag, or "build" if a Dockerfile is needed
    fleet_singleton: bool = False  # True = runs once fleet-wide, not per-decky

    # Per-service customizable fields exposed to the Inspector UI.
    # Subclasses override; default empty -> "No customizable fields".
    config_schema: list[ServiceConfigField] = []

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

    def udp_ports(self, cfg: dict | None = None) -> list[int]:
        """UDP ports this service needs published, given its resolved config.

        Only meaningful for gateway deckies in topology deployments where the
        base container publishes ports on the host.  Fleet deckies use MACVLAN
        and need no port publishing at all.  Default: no UDP ports.
        """
        return []

    def validate_cfg(self, cfg: dict | None) -> dict:
        """
        Coerce a user-submitted dict against this service's config_schema.

        Unknown keys are silently dropped. Declared keys are coerced to their
        declared type (raising ConfigValidationError on bad values). Empty
        strings on optional fields drop the key entirely so compose_fragment's
        existing `if "X" in cfg` guards keep working.
        """
        out: dict[str, Any] = {}
        if not cfg:
            return out
        by_key = {f.key: f for f in self.config_schema}
        for key, raw in cfg.items():
            spec = by_key.get(key)
            if spec is None:
                continue  # drop unknown keys
            if raw is None or raw == "":
                continue
            out[key] = _coerce(spec, raw)
        return out


def _coerce(spec: ServiceConfigField, raw: Any) -> Any:
    t = spec.type
    if t in ("string", "password"):
        return str(raw)
    if t == "textarea":
        s = str(raw)
        if s.startswith(TEXTAREA_B64_PREFIX):
            try:
                return base64.b64decode(s[len(TEXTAREA_B64_PREFIX):], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError) as e:
                raise ConfigValidationError(
                    f"{spec.key}: malformed {TEXTAREA_B64_PREFIX} payload"
                ) from e
        return s
    if t == "int":
        try:
            return int(raw)
        except (TypeError, ValueError) as e:
            raise ConfigValidationError(f"{spec.key}: expected int, got {raw!r}") from e
    if t == "bool":
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            if raw.lower() in ("true", "1", "yes", "on"):
                return True
            if raw.lower() in ("false", "0", "no", "off"):
                return False
        raise ConfigValidationError(f"{spec.key}: expected bool, got {raw!r}")
    if t == "enum":
        s = str(raw)
        if spec.enum and s not in spec.enum:
            raise ConfigValidationError(
                f"{spec.key}: {s!r} not in allowed values {spec.enum}"
            )
        return s
    if t == "multi_enum":
        if not isinstance(raw, list):
            raise ConfigValidationError(
                f"{spec.key}: expected list, got {type(raw).__name__}"
            )
        if not raw:
            raise ConfigValidationError(f"{spec.key}: list must not be empty")
        seen: set[str] = set()
        result: list[str] = []
        for item in raw:
            s = str(item)
            if spec.enum and s not in spec.enum:
                raise ConfigValidationError(
                    f"{spec.key}: {s!r} not in allowed values {spec.enum}"
                )
            if s not in seen:
                seen.add(s)
                result.append(s)
        return result
    raise ConfigValidationError(f"{spec.key}: unknown field type {t!r}")
