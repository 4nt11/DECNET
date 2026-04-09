import os
from pathlib import Path
from dotenv import load_dotenv

# Calculate absolute path to the project root
_ROOT: Path = Path(__file__).parent.parent.absolute()

# Load .env.local first, then fallback to .env
load_dotenv(_ROOT / ".env.local")
load_dotenv(_ROOT / ".env")

# API Options
DECNET_API_HOST: str = os.environ.get("DECNET_API_HOST", "0.0.0.0")  # nosec B104
DECNET_API_PORT: int = int(os.environ.get("DECNET_API_PORT", "8000"))
DECNET_JWT_SECRET: str = os.environ.get("DECNET_JWT_SECRET", "fallback-secret-key-change-me")
DECNET_INGEST_LOG_FILE: str | None = os.environ.get("DECNET_INGEST_LOG_FILE", "/var/log/decnet/decnet.log")

# Web Dashboard Options
DECNET_WEB_HOST: str = os.environ.get("DECNET_WEB_HOST", "0.0.0.0")  # nosec B104
DECNET_WEB_PORT: int = int(os.environ.get("DECNET_WEB_PORT", "8080"))
DECNET_ADMIN_USER: str = os.environ.get("DECNET_ADMIN_USER", "admin")
DECNET_ADMIN_PASSWORD: str = os.environ.get("DECNET_ADMIN_PASSWORD", "admin")
DECNET_DEVELOPER: bool = os.environ.get("DECNET_DEVELOPER", "False").lower() == "true"
