"""
DECNET Domain Models.
Centralized repository for all Pydantic specifications used throughout the project.
This file ensures that core domain logic has no dependencies on the web or database layers.
"""
from typing import Optional, List, Dict, Literal, Annotated, Any
from pydantic import BaseModel, ConfigDict, Field as PydanticField, field_validator, BeforeValidator
import configparser


# --- INI Specification Models ---

def validate_ini_string(v: Any) -> str:
    """Structural validator for DECNET INI strings using configparser."""
    if not isinstance(v, str):
        # This remains an internal type mismatch (caught by Pydantic usually)
        raise ValueError("INI content must be a string")

    # 512KB limit to prevent DoS/OOM
    if len(v) > 512 * 1024:
        raise ValueError("INI content is too large (max 512KB)")

    if not v.strip():
        # Using exact phrasing expected by tests
        raise ValueError("INI content is empty")

    parser = configparser.ConfigParser(interpolation=None, allow_no_value=True, strict=False)
    try:
        parser.read_string(v)
        if not parser.sections():
             raise ValueError("The provided INI content must contain at least one section (no sections found)")
    except configparser.Error as e:
        # If it's a generic parsing error, we check if it's effectively a "missing sections" error
        if "no section headers" in str(e).lower():
            raise ValueError("Invalid INI format: no sections found")
        raise ValueError(f"Invalid INI format: {str(e)}")

    return v

# Reusable type that enforces INI structure during initialization.
# Removed min_length=1 to make empty strings schema-compliant yet semantically invalid (mapped to 409).
IniContent = Annotated[str, BeforeValidator(validate_ini_string)]

class DeckySpec(BaseModel):
    """Configuration spec for a single decky as defined in the INI file."""
    model_config = ConfigDict(strict=True, extra="forbid")
    name: str = PydanticField(..., max_length=128, pattern=r"^[A-Za-z0-9\-_.]+$")
    ip: Optional[str] = None
    services: Optional[List[str]] = None
    archetype: Optional[str] = None
    service_config: Dict[str, Dict] = PydanticField(default_factory=dict)
    nmap_os: Optional[str] = None
    mutate_interval: Optional[int] = PydanticField(None, ge=1)


class CustomServiceSpec(BaseModel):
    """Spec for a user-defined (bring-your-own) service."""
    model_config = ConfigDict(strict=True, extra="forbid")
    name: str
    image: str
    exec_cmd: str
    ports: List[int] = PydanticField(default_factory=list)


class IniConfig(BaseModel):
    """The complete structured representation of a DECNET INI file."""
    model_config = ConfigDict(strict=True, extra="forbid")
    subnet: Optional[str] = None
    gateway: Optional[str] = None
    interface: Optional[str] = None
    mutate_interval: Optional[int] = PydanticField(None, ge=1)
    deckies: List[DeckySpec] = PydanticField(default_factory=list, min_length=1)
    custom_services: List[CustomServiceSpec] = PydanticField(default_factory=list)

    @field_validator("deckies")
    @classmethod
    def at_least_one_decky(cls, v: List[DeckySpec]) -> List[DeckySpec]:
        """Ensure that an INI deployment always contains at least one machine."""
        if not v:
            raise ValueError("INI must contain at least one decky section")
        return v


# --- Runtime Configuration Models ---

class DeckyConfig(BaseModel):
    """Full operational configuration for a deployed decky container."""
    model_config = ConfigDict(strict=True, extra="forbid")
    name: str
    ip: str
    services: list[str] = PydanticField(..., min_length=1)
    distro: str          # slug from distros.DISTROS, e.g. "debian", "ubuntu22"
    base_image: str      # Docker image for the base/IP-holder container
    build_base: str = "debian:bookworm-slim"  # apt-compatible image for service Dockerfiles
    hostname: str
    archetype: str | None = None  # archetype slug if spawned from an archetype profile
    service_config: dict[str, dict] = PydanticField(default_factory=dict)
    nmap_os: str = "linux"        # OS family for TCP/IP stack spoofing (see os_fingerprint.py)
    mutate_interval: int | None = None  # automatic rotation interval in minutes
    last_mutated: float = 0.0     # timestamp of last mutation
    last_login_attempt: float = 0.0 # timestamp of most recent interaction
    # SWARM: the SwarmHost.uuid that runs this decky. None in unihost mode
    # so existing state files deserialize unchanged.
    host_uuid: str | None = None

    @field_validator("services")
    @classmethod
    def services_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("A decky must have at least one service.")
        return v


class DecnetConfig(BaseModel):
    """Root configuration for the entire DECNET fleet deployment."""
    mode: Literal["unihost", "swarm"]
    interface: str
    subnet: str
    gateway: str
    deckies: list[DeckyConfig] = PydanticField(..., min_length=1)
    log_file: str | None = None    # host path where the collector writes the log file
    ipvlan: bool = False           # use IPvlan L2 instead of MACVLAN (WiFi-friendly)
    mutate_interval: int | None = 30 # global automatic rotation interval in minutes
