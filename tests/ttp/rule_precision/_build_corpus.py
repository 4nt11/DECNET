"""Extract a labelled corpus from the production sqlite DB.

Run on the operator workstation against a real ``decnet-prod.db``.
Outputs ``corpus/commands.jsonl`` (gitignored).

**IP exclusion is mandatory and operator-supplied.** The operator's
own source IP, plus any other addresses that must never end up in a
committed/inspected corpus, are passed via ``--exclude-ip`` (repeatable)
or the ``DECNET_TTP_CORPUS_EXCLUDE_IPS`` env var (comma-separated).
The script refuses to run with an empty exclusion list — extracting
attacker payloads without a vetted blocklist is a doxxing footgun and
that mistake is not allowed to happen silently.

Usage::

    DECNET_TTP_CORPUS_EXCLUDE_IPS="<your-ip>,<other>" \\
    python -m tests.ttp.rule_precision._build_corpus \\
        --db /path/to/decnet-prod.db \\
        --out tests/ttp/rule_precision/corpus
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_CMD_RE = re.compile(r"\bcmd=(.*)$")
_ENV_VAR = "DECNET_TTP_CORPUS_EXCLUDE_IPS"


def _extract_cmd(raw_line: str) -> str | None:
    match = _CMD_RE.search(raw_line)
    if match is None:
        return None
    cmd = match.group(1).strip()
    return cmd or None


def _scrub_ips(text: str, excludes: Iterable[str]) -> str:
    out = text
    for ip in excludes:
        out = out.replace(ip, "0.0.0.0")
    return out


def _resolve_excludes(cli: list[str]) -> list[str]:
    env = os.environ.get(_ENV_VAR, "")
    env_parts = [chunk.strip() for chunk in env.split(",") if chunk.strip()]
    merged = sorted({*cli, *env_parts})
    return merged


def build_command_corpus(
    db_path: Path,
    out_path: Path,
    excludes: list[str],
) -> int:
    """Write ``commands.jsonl`` from the prod DB. Returns row count."""
    if not excludes:
        raise RuntimeError(
            "refusing to extract corpus with empty IP exclusion list — "
            f"set --exclude-ip or {_ENV_VAR}",
        )
    placeholders = ",".join("?" * len(excludes))
    sql = (
        "SELECT raw_line FROM logs "
        "WHERE event_type IN ('command', 'unknown_command') "
        f"AND attacker_ip NOT IN ({placeholders})"
    )
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with sqlite3.connect(db_path) as con:
        for (raw,) in con.execute(sql, excludes):
            cmd = _extract_cmd(raw)
            if cmd is None or cmd in seen:
                continue
            seen.add(cmd)
            scrubbed = _scrub_ips(cmd, excludes)
            rows.append({
                "source_kind": "command",
                "payload": {"command_text": scrubbed},
                "expected_rule_ids": [],
                "label": f"prod-{len(rows):04d}",
            })
    out_path.mkdir(parents=True, exist_ok=True)
    target = out_path / "commands.jsonl"
    with target.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--exclude-ip",
        action="append",
        default=[],
        help=(
            "IP to drop from the SQL pull AND scrub from cmd payloads. "
            f"Repeatable. Merged with ${_ENV_VAR}. At least one "
            "exclusion is mandatory."
        ),
    )
    args = parser.parse_args(argv)
    excludes = _resolve_excludes(args.exclude_ip)
    n = build_command_corpus(args.db, args.out, excludes)
    print(f"wrote {n} command rows to {args.out / 'commands.jsonl'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
