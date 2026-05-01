# Static Types Improvement Map

Generated: 2026-04-30  
Command: `.311/bin/mypy decnet/ --ignore-missing-imports --no-error-summary`

---

## Error Summary (real mypy codes only)

| Code | Count | Meaning |
|------|-------|---------|
| `attr-defined` | 258 | accessing attribute that doesn't exist |
| `arg-type` | 226 | wrong argument type passed to function |
| `union-attr` | 141 | accessing attr on `X \| None` without narrowing |
| `unused-ignore` | 23 | stale `# type: ignore` comment |
| `call-overload` | 22 | no matching overload for call |
| `assignment` | 18 | incompatible type in assignment |
| `index` | 18 | indexing a value that may be None |
| `call-arg` | 11 | missing or unexpected argument |
| `misc` | 9 | miscellaneous |
| `var-annotated` | 6 | unannotated variable needs explicit type |
| `func-returns-value` | 4 | using return value of void function |
| `return-value` | 2 | wrong return type |
| `override` | 2 | incompatible method override |
| `import-untyped` | 2 | third-party library missing stubs |
| `abstract` | 1 | instantiating abstract class |
| `syntax` | 1 | syntax error caught by mypy |

**Total real errors: ~762**

---

## Files with Most Errors

| File | Errors |
|------|--------|
| `decnet/templates/pop3/server.py` | 41 |
| `decnet/web/db/sqlmodel_repo/canary.py` | 34 |
| `decnet/web/db/sqlmodel_repo/orchestrator.py` | 31 |
| `decnet/web/db/sqlmodel_repo/attackers/activity.py` | 28 |
| `decnet/templates/smtp/server.py` | 27 |
| `decnet/web/db/sqlmodel_repo/identities.py` | 26 |
| `decnet/web/db/sqlmodel_repo/credentials/_core.py` | 26 |
| `decnet/web/db/sqlmodel_repo/topology/_core.py` | 24 |
| `decnet/web/db/sqlmodel_repo/campaigns.py` | 24 |
| `decnet/web/db/sqlmodel_repo/realism.py` | 22 |
| `decnet/web/db/sqlmodel_repo/credentials/reuse.py` | 22 |
| `decnet/web/db/sqlmodel_repo/logs.py` | 21 |
| `decnet/web/db/sqlmodel_repo/bounties.py` | 21 |
| `decnet/web/db/sqlmodel_repo/webhooks.py` | 19 |
| `decnet/web/db/sqlmodel_repo/attackers/_core.py` | 16 |
| `decnet/templates/mqtt/server.py` | 16 |
| `decnet/web/db/sqlmodel_repo/topology/lans.py` | 15 |
| `decnet/web/db/sqlmodel_repo/topology/deckies.py` | 15 |
| `decnet/web/db/sqlmodel_repo/fleet.py` | 14 |
| `decnet/web/db/sqlmodel_repo/topology/mutations.py` | 13 |
| `decnet/web/db/sqlmodel_repo/swarm.py` | 13 |
| `decnet/web/db/sqlmodel_repo/auth.py` | 12 |
| `decnet/templates/postgres/server.py` | 12 |
| `decnet/web/db/sqlmodel_repo/topology/edges.py` | 11 |

---

## Priority Path (do these in order)

### P0 — One fix, 30+ errors gone (highest ROI)

**`syslog_bridge.py` `binascii` ghost import** (~30 `attr-defined`)  
Every single `decnet/templates/*/syslog_bridge.py` hits the same error at line 147:
```
Module has no attribute "binascii"
```
This is a templated copy. Fix the import in the base (`decnet/templates/syslog_bridge.py`) and propagate to all template copies. **One root cause, ~30 files affected.**

**`ntlmssp.py` `str | None` assignment** (3 `assignment`)  
`decnet/templates/_shared/ntlmssp.py:123` — same bug copied to `smb/` and `rdp/`:
```
expression has type "str | None", variable has type "str"
```
Fix the shared version and propagate to both copies. Correct approach: narrow with `if val is None: raise ValueError(...)` at the parse boundary, or widen the variable annotation to `str | None` and handle downstream.

---

### P1 — Quick isolated fixes

**`decnet/services/registry.py:31`** — `[abstract]`  
Instantiating `BaseService` which has abstract `compose_fragment`. Either make it concrete or fix the call site.

**`decnet/ini_loader.py:69`** — `[call-arg]`  
`IniConfig` missing required argument `mutate_interval`. Either add it to the call or give it a default value in the dataclass.

**`decnet/topology/compose.py:23`** and **`decnet/composer.py`** — `[import-untyped]`  
Install stub: `.311/bin/pip install types-PyYAML`

**`decnet/geoip/rir/provider.py:48`** and **`decnet/asn/iptoasn/provider.py:57`** — `[var-annotated]`  
Add explicit type annotation to `ranges`. Pattern: `ranges: list[tuple[int, int]] = []` (adjust element type to match actual usage).

**`decnet/templates/elasticsearch/server.py:124`** — `[arg-type]`  
`list[Never]` passed where `dict[Any, Any]` expected. `[]` should be `{}`.

**Stale `# type: ignore` comments** (23 `[unused-ignore]`)  
`decnet/clustering/impl/similarity.py:268`, `decnet/clustering/campaign/impl/similarity.py:345`, several in `decnet/logging/__init__.py`, `decnet/canary/`. Remove them — the underlying issues were fixed but the ignores weren't cleaned up.

---

### P2 — `sqlmodel_repo` bulk fix (`union-attr`, `arg-type`, ~350 errors)

The entire `decnet/web/db/sqlmodel_repo/` subtree has a pervasive pattern:

```python
result = session.exec(stmt).first()  # returns X | None
result.some_attr                     # error: Item "None" of "X | None"
```

Strategy:
- Where `None` is a bug: raise `HTTPException` or a domain exception immediately after the query if result is `None`. This is the correct repo-layer pattern — let callers handle 404.
- Where `None` is valid: annotate the variable as `X | None` and gate downstream access with an explicit `if result is not None:` branch.
- Start with highest-error files: `canary.py` (34), `orchestrator.py` (31), `attackers/activity.py` (28).

---

### P3 — Template server protocol types (`union-attr`, ~100 errors)

`decnet/templates/pop3/server.py` (41), `smtp/server.py` (27), `postgres/server.py` (12), `rdp/server.py`, `mqtt/server.py`, etc.

Pattern:
```python
self.transport = None  # inferred as None, never annotated
self.transport.write(...)  # union-attr: Item "None" of "... | None"
```

Fix: annotate `transport` properly at class level:
```python
from asyncio import Transport
transport: Transport | None = None
```
Then guard each call site with `if self.transport is not None:` or raise in `connection_made` if transport is unexpectedly None.

---

### P4 — `call-overload` (22 errors)

Scattered across multiple files. These require per-site investigation — likely SQLModel `.exec()` or similar overloaded methods receiving wrong types. Tackle after P2 since many may disappear once the repo files are cleaned.

---

## Recommended mypy config additions (pyproject.toml)

Once P0–P1 are done, add to `[tool.mypy]`:

```toml
[tool.mypy]
ignore_missing_imports = true
warn_unused_ignores = true       # catches stale type: ignore
warn_return_any = false          # too noisy until P2 done
check_untyped_defs = false       # enable after P3
```

Enable `check_untyped_defs = true` as the final step once the repo is clean.

---

## Quick-win checklist

- [x] Fix `syslog_bridge.py` base `binascii` import + propagate to all template copies (P0, ~30 errors)
- [x] Fix `templates/_shared/ntlmssp.py:123` + smb/rdp copies (P0, 3 errors)
- [x] `pip install types-PyYAML` + add `pydantic.mypy` plugin to `[tool.mypy]` (P1, 2 errors)
- [x] Fix `services/registry.py:31` abstract instantiation (P1, 1 error)
- [x] Fix `ini_loader.py:69` missing `mutate_interval` arg — resolved by pydantic plugin (P1, 1 error)
- [x] Fix `elasticsearch/server.py` `_send_json` signature: `dict` → `dict | list` (P1, 1 error)
- [x] Remove 2 stale `# type: ignore[no-untyped-def]` in clustering adapters; kept logging/canary ignores as valid (P1)
- [x] Annotate `ranges` in `geoip/rir/provider.py` and `asn/iptoasn/provider.py` (P1, 2 errors)
- [ ] Sweep `sqlmodel_repo/` with proper None-guard raises (P2, ~350 errors)
- [ ] Annotate `transport` in template servers + guard call sites (P3, ~100 errors)
