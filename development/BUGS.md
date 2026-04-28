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

---

## BUG-003 — SSE `/api/v1/stream` proxy BrokenPipe storm

**Detected:** 2026-04-17
**Status:** Open — do not fix, testing first

**Symptom:** The web-dashboard CLI proxy hammers `BrokenPipeError: [Errno 32] Broken pipe` on `GET /api/v1/stream` and answers with 502s. The SSE client reconnects, a handful succeed (200), then the next chunk write fails again:

```
decnet.cli - web proxy error GET /api/v1/stream?token=...: [Errno 32] Broken pipe
decnet.cli - web code 502, message API proxy error: [Errno 32] Broken pipe
...
File "/home/anti/Tools/DECNET/decnet/cli.py", line 790, in _proxy
    self.wfile.write(chunk)
BrokenPipeError: [Errno 32] Broken pipe
```

During the failure the proxy also tries to `send_error(502, ...)` on the already-closed socket, producing a second BrokenPipe and a noisy traceback.

**Root cause (suspected, unconfirmed):** the stdlib `http.server`-based proxy in `decnet/cli.py:_proxy` doesn't handle the browser closing the SSE socket cleanly — any `wfile.write(chunk)` after the client disconnects raises `BrokenPipe`, and then the error path itself writes to the dead socket. Upstream uvicorn SSE generator is probably fine; the proxy layer is the fragile piece.

**Fix:** Deferred. Likely options when we get back to it:
- Catch `BrokenPipeError` / `ConnectionResetError` inside `_proxy` and silently close instead of `send_error` (writing headers to a dead socket is always going to fail).
- Replace the threaded stdlib proxy with something that understands streaming and disconnect signals properly.
- Or bypass the proxy for `/api/v1/stream` specifically and let the browser hit the API directly (CORS permitting).

**Impact:** Dashboard SSE is unusable under any real load; the API itself is unaffected.
