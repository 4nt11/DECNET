import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Calculate absolute path to the project root
_ROOT: Path = Path(__file__).parent.parent.absolute()

# Load .env.local first, then fallback to .env
load_dotenv(_ROOT / ".env.local")
load_dotenv(_ROOT / ".env")


def _port(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"Environment variable '{name}' must be an integer, got '{raw}'.")
    if not (1 <= value <= 65535):
        raise ValueError(f"Environment variable '{name}' must be 1–65535, got {value}.")
    return value


def _require_env(name: str) -> str:
    """Return the env var value or raise at startup if it is unset or a known-bad default."""
    _KNOWN_BAD = {"fallback-secret-key-change-me", "admin", "secret", "password", "changeme"}
    value = os.environ.get(name)
    if not value:
        raise ValueError(
            f"Required environment variable '{name}' is not set. "
            f"Set it in .env.local or export it before starting DECNET."
        )

    if any(k.startswith("PYTEST") for k in os.environ):
        return value

    if value.lower() in _KNOWN_BAD:
        raise ValueError(
            f"Environment variable '{name}' is set to an insecure default ('{value}'). "
            f"Choose a strong, unique value before starting DECNET."
        )
    return value


# API Options
DECNET_API_HOST: str = os.environ.get("DECNET_API_HOST", "0.0.0.0")  # nosec B104
DECNET_API_PORT: int = _port("DECNET_API_PORT", 8000)
DECNET_JWT_SECRET: str = _require_env("DECNET_JWT_SECRET")
DECNET_INGEST_LOG_FILE: str | None = os.environ.get("DECNET_INGEST_LOG_FILE", "/var/log/decnet/decnet.log")

# Web Dashboard Options
DECNET_WEB_HOST: str = os.environ.get("DECNET_WEB_HOST", "0.0.0.0")  # nosec B104
DECNET_WEB_PORT: int = _port("DECNET_WEB_PORT", 8080)
DECNET_ADMIN_USER: str = os.environ.get("DECNET_ADMIN_USER", "admin")
DECNET_ADMIN_PASSWORD: str = os.environ.get("DECNET_ADMIN_PASSWORD", "admin")
DECNET_DEVELOPER: bool = os.environ.get("DECNET_DEVELOPER", "False").lower() == "true"

# Database Options
DECNET_DB_TYPE: str = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()
DECNET_DB_URL: Optional[str] = os.environ.get("DECNET_DB_URL")

# CORS — comma-separated list of allowed origins for the web dashboard API.
# Defaults to the configured web host/port. Override with DECNET_CORS_ORIGINS if needed.
# Example: DECNET_CORS_ORIGINS=http://192.168.1.50:9090,https://dashboard.example.com
_web_hostname: str = "localhost" if DECNET_WEB_HOST in ("0.0.0.0", "127.0.0.1", "::") else DECNET_WEB_HOST  # nosec B104
_cors_default: str = f"http://{_web_hostname}:{DECNET_WEB_PORT}"
_cors_raw: str = os.environ.get("DECNET_CORS_ORIGINS", _cors_default)
DECNET_CORS_ORIGINS: list[str] = [o.strip() for o in _cors_raw.split(",") if o.strip()]
