"""Shared column/validator helpers used across model domain modules."""
from datetime import datetime
from typing import Annotated, Any, Optional

from pydantic import BeforeValidator
from sqlalchemy import Text
from sqlalchemy.dialects.mysql import MEDIUMTEXT

# Use on columns that accumulate over an attacker's lifetime (commands,
# fingerprints, state blobs).  TEXT on MySQL caps at 64 KiB; MEDIUMTEXT
# stretches to 16 MiB.  SQLite has no fixed-width text types so Text()
# stays unchanged there.
_BIG_TEXT = Text().with_variant(MEDIUMTEXT(), "mysql")


def _normalize_null(v: Any) -> Any:
    if isinstance(v, str) and v.lower() in ("null", "undefined", ""):
        return None
    return v


NullableDatetime = Annotated[Optional[datetime], BeforeValidator(_normalize_null)]
NullableString = Annotated[Optional[str], BeforeValidator(_normalize_null)]
