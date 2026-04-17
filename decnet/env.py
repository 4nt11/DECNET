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
    if name == "DECNET_JWT_SECRET" and len(value) < 32:
        _developer = os.environ.get("DECNET_DEVELOPER", "False").lower() == "true"
        if not _developer:
            raise ValueError(
                f"DECNET_JWT_SECRET is too short ({len(value)} bytes). "
                f"Use at least 32 characters to satisfy HS256 requirements (RFC 7518 §3.2)."
            )
    return value


# System logging — all microservice daemons append here.
DECNET_SYSTEM_LOGS: str = os.environ.get("DECNET_SYSTEM_LOGS", "decnet.system.log")

# Set to "true" to embed the profiler inside the API process.
# Leave unset (default) when the standalone `decnet profiler --daemon` is
# running — embedding both produces two workers sharing the same DB cursor,
# which causes events to be skipped or processed twice.
DECNET_EMBED_PROFILER: bool = os.environ.get("DECNET_EMBED_PROFILER", "").lower() == "true"

# Set to "true" to mount the Pyinstrument ASGI middleware on the FastAPI app.
# Produces per-request HTML flamegraphs under ./profiles/. Off by default so
# production and normal dev runs pay zero profiling overhead.
DECNET_PROFILE_REQUESTS: bool = os.environ.get("DECNET_PROFILE_REQUESTS", "").lower() == "true"
DECNET_PROFILE_DIR: str = os.environ.get("DECNET_PROFILE_DIR", "profiles")

# API Options
DECNET_API_HOST: str = os.environ.get("DECNET_API_HOST", "127.0.0.1")
DECNET_API_PORT: int = _port("DECNET_API_PORT", 8000)
DECNET_JWT_SECRET: str = _require_env("DECNET_JWT_SECRET")
DECNET_INGEST_LOG_FILE: str | None = os.environ.get("DECNET_INGEST_LOG_FILE", "/var/log/decnet/decnet.log")

# Web Dashboard Options
DECNET_WEB_HOST: str = os.environ.get("DECNET_WEB_HOST", "127.0.0.1")
DECNET_WEB_PORT: int = _port("DECNET_WEB_PORT", 8080)
DECNET_ADMIN_USER: str = os.environ.get("DECNET_ADMIN_USER", "admin")
DECNET_ADMIN_PASSWORD: str = os.environ.get("DECNET_ADMIN_PASSWORD", "admin")
DECNET_DEVELOPER: bool = os.environ.get("DECNET_DEVELOPER", "False").lower() == "true"

# Tracing — set to "true" to enable OpenTelemetry distributed tracing.
# Separate from DECNET_DEVELOPER so tracing can be toggled independently.
DECNET_DEVELOPER_TRACING: bool = os.environ.get("DECNET_DEVELOPER_TRACING", "").lower() == "true"
DECNET_OTEL_ENDPOINT: str = os.environ.get("DECNET_OTEL_ENDPOINT", "http://localhost:4317")

# Database Options
DECNET_DB_TYPE: str = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()
DECNET_DB_URL: Optional[str] = os.environ.get("DECNET_DB_URL")
# MySQL component vars (used only when DECNET_DB_URL is not set)
DECNET_DB_HOST: str = os.environ.get("DECNET_DB_HOST", "localhost")
DECNET_DB_PORT: int = _port("DECNET_DB_PORT", 3306) if os.environ.get("DECNET_DB_PORT") else 3306
DECNET_DB_NAME: str = os.environ.get("DECNET_DB_NAME", "decnet")
DECNET_DB_USER: str = os.environ.get("DECNET_DB_USER", "decnet")
DECNET_DB_PASSWORD: Optional[str] = os.environ.get("DECNET_DB_PASSWORD")

# CORS — comma-separated list of allowed origins for the web dashboard API.
# Defaults to the configured web host/port. Override with DECNET_CORS_ORIGINS if needed.
# Example: DECNET_CORS_ORIGINS=http://192.168.1.50:9090,https://dashboard.example.com
_WILDCARD_ADDRS = {"0.0.0.0", "127.0.0.1", "::"}  # nosec B104 — comparison only, not a bind
_web_hostname: str = "localhost" if DECNET_WEB_HOST in _WILDCARD_ADDRS else DECNET_WEB_HOST
_cors_default: str = f"http://{_web_hostname}:{DECNET_WEB_PORT}"
_cors_raw: str = os.environ.get("DECNET_CORS_ORIGINS", _cors_default)
DECNET_CORS_ORIGINS: list[str] = [o.strip() for o in _cors_raw.split(",") if o.strip()]
