"""Vulture whitelist — names that look unused but aren't.

Run via:

    vulture decnet vulture_whitelist.py --min-confidence 80

Each entry suppresses a known false positive. Add a comment with the
file:line and the reason so future-you can revisit.
"""

# FastAPI auth dependencies — `Depends()` runs for the side effect
# (auth/RBAC enforcement) even when the injected value is unused inside
# the handler body. Vulture can't see that.
viewer  # decnet/web/router/canary/api_tokens.py:176, 198, 284 — Depends(require_viewer)
admin   # any handler with admin: dict = Depends(require_admin) where the body doesn't read it
user    # any handler with user: dict = Depends(require_user) where the body doesn't read it

# IMAP stub — UID SEARCH vs sequence SEARCH is a real protocol
# differentiator, but in this honeypot stub UID == seq number (see the
# "UID == sequence number" comment at the top of the email fixtures), so
# the parameter is intentionally a no-op.
uid_mode  # decnet/templates/imap/server.py:646
