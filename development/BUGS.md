# BUGS

Active bugs detected during development. Do not fix until noted otherwise.

---

## BUG-001 — Split-brain model imports across router files (Gemini SQLModel migration)

**Detected:** 2026-04-09  
**Status:** Open — do not fix, migration in progress

**Symptom:** `from decnet.web.api import app` fails with `ModuleNotFoundError: No module named 'decnet.web.models'`

**Root cause:** Gemini's SQLModel migration is partially complete. Models were moved to `decnet/web/db/models.py`, but three router files were not updated and still import from the old `decnet.web.models` path:

| File | Stale import |
|------|--------------|
| `decnet/web/router/auth/api_login.py:12` | `from decnet.web.models import LoginRequest, Token` |
| `decnet/web/router/auth/api_change_pass.py:7` | `from decnet.web.models import ChangePasswordRequest` |
| `decnet/web/router/stats/api_get_stats.py:6` | `from decnet.web.models import StatsResponse` |

**Fix:** Update those three files to import from `decnet.web.db.models` (consistent with the other router files already migrated).

**Impact:** All `tests/api/` tests fail to collect. Web server cannot start.

---

## BUG-002 — `decnet/web/db/sqlite/repository.py` depends on `sqlalchemy` directly

**Detected:** 2026-04-09  
**Status:** Resolved (dependency installed via `pip install -e ".[dev]"`)

**Symptom:** `ModuleNotFoundError: No module named 'sqlalchemy'` before `sqlmodel` was installed.

**Root cause:** `sqlmodel>=0.0.16` was added to `pyproject.toml` but `pip install -e .` had not been re-run in the dev environment.

**Fix:** Run `pip install -e ".[dev]"`. Already applied.
