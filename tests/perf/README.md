# DECNET Profiling

Five complementary lenses. Pick whichever answers the question you have.

## 1. Whole-process sampling — py-spy

> **Note:** py-spy 0.4.1 (latest on PyPI as of 2026-04) does **not** yet support
> Python 3.14, which DECNET currently runs on. Attaching fails with
> *"No python processes found in process <pid>"* even when uvicorn is clearly
> running. Use lenses 2–5 until upstream ships 3.14 support
> (track https://github.com/benfred/py-spy/releases). The wrapper script aborts
> with a clear message when it detects 3.14+.

Attach to a running API and record a flamegraph for 30s. Requires `sudo`
(Linux ptrace scope).

```bash
./scripts/profile/pyspy-attach.sh               # auto-finds uvicorn pid
sudo py-spy record -o profile.svg -p <PID> -d 30 --subprocesses
```

Other common failure modes (when py-spy *does* support your Python):
- Attached to the Typer CLI PID, not the uvicorn worker PID (use `pgrep -f 'uvicorn decnet.web.api'`).
- `kernel.yama.ptrace_scope=1` — run with `sudo` or `sudo sysctl kernel.yama.ptrace_scope=0`.
- The API isn't actually running (a `--dry-run` deploy starts nothing).

## 2. Per-request flamegraphs — Pyinstrument

Set the env flag, hit endpoints, find HTML flamegraphs under `./profiles/`.

```bash
DECNET_PROFILE_REQUESTS=true decnet deploy --mode unihost --deckies 1
# in another shell:
curl http://127.0.0.1:8000/api/v1/health
open profiles/*.html
```

Off by default — zero overhead when the flag is unset.

## 3. Deterministic call graph — cProfile + snakeviz

For one-shot profiling of CLI commands or scripts.

```bash
./scripts/profile/cprofile-cli.sh services      # profiles `decnet services`
snakeviz profiles/cprofile.prof
```

## 4. Micro-benchmarks — pytest-benchmark

Regression-gate repository hot paths.

```bash
pytest -m bench tests/perf/ -n0                 # SQLite backend (default)
DECNET_DB_TYPE=mysql pytest -m bench tests/perf/ -n0
```

Note: `-n0` disables xdist. `pytest-benchmark` refuses to measure under
parallel workers, which is the project default (`-n logical --dist loadscope`).

## 5. Memory allocation — memray

Hunt leaks and allocation hot spots in the API / workers.

```bash
./scripts/profile/memray-api.sh                 # runs uvicorn under memray
memray flamegraph profiles/memray.bin
```

## Load generation

Pair any of the in-process lenses (2, 5) with Locust for realistic traffic:

```bash
pytest -m stress tests/stress/
```
