"""Per-mint JS obfuscator wrapper.

Thin Python wrapper around the ``javascript-obfuscator`` Node package.
Used by the fingerprint generators / instrumenters to produce a unique,
hard-to-statically-analyse JS blob per canary mint.

Two design choices flow from the canary contract in :mod:`base`:

* **Determinism.** Generators must return byte-identical artifacts for
  the same ``(callback_token, http_base, dns_zone, persona)``.  We
  derive a numeric seed from the callback token and pass it to the
  obfuscator's own ``seed`` option, and we derive the polymorphic
  config bits from the same hash so a re-mint reproduces exactly.
* **Per-mint uniqueness.** Two different callback tokens produce
  structurally different output: different identifier names, different
  string-array rotation, optionally different transforms enabled.

The Node helper at ``_obfuscate_helper.js`` is invoked via subprocess.
We pass code+options as JSON on stdin and read the obfuscated result
from stdout.  Stderr surfaces obfuscator failures.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

_HELPER = Path(__file__).parent / "_obfuscate_helper.js"
_PAYLOAD = Path(__file__).parent / "fingerprint_payload.js"

# Node binary path. Honor DECNET_NODE_BIN so deployments can pin a
# specific runtime; default to PATH lookup.
_NODE_BIN = os.environ.get("DECNET_NODE_BIN", "node")

# Hard timeout for the obfuscator subprocess. Real runs on the
# fingerprint payload sit well under 5s on a dev box.
_TIMEOUT_S = 30


class ObfuscatorError(RuntimeError):
    """Raised when the Node helper fails or returns empty output."""


def _seed_from_token(callback_token: str) -> int:
    """Derive a 31-bit numeric seed from the callback token.

    ``javascript-obfuscator`` expects ``seed: number`` (int32-ish);
    using a SHA-256-derived prefix gives us a uniform distribution
    across the 31-bit positive range.
    """
    h = hashlib.sha256(callback_token.encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big") & 0x7FFFFFFF


def _config_from_seed(seed: int) -> dict[str, Any]:
    """Build a deterministic, per-mint obfuscator config.

    The hash bits drive *which* transforms apply — two mints get
    structurally different outputs, not just different identifier names.
    Defaults stay aggressive enough that reverse engineering is real
    work; we never disable string-array or rename, only vary the dial.
    """
    bits = seed
    encodings = ("base64", "rc4")
    string_array_encoding = [encodings[bits & 1]]
    control_flow_threshold = 0.5 + ((bits >> 1) & 0xFF) / 512.0  # 0.5 .. ~1.0
    dead_code_threshold = 0.2 + ((bits >> 9) & 0xFF) / 512.0  # 0.2 .. ~0.7
    transform_object_keys = bool((bits >> 17) & 1)
    numbers_to_expressions = bool((bits >> 18) & 1)
    simplify = bool((bits >> 19) & 1)
    return {
        "compact": True,
        "seed": seed,
        "controlFlowFlattening": True,
        "controlFlowFlatteningThreshold": round(control_flow_threshold, 3),
        "deadCodeInjection": True,
        "deadCodeInjectionThreshold": round(dead_code_threshold, 3),
        "stringArray": True,
        "stringArrayEncoding": string_array_encoding,
        "stringArrayThreshold": 1,
        "stringArrayRotate": True,
        "stringArrayShuffle": True,
        "splitStrings": True,
        "splitStringsChunkLength": 4 + (bits & 7),
        "transformObjectKeys": transform_object_keys,
        "numbersToExpressions": numbers_to_expressions,
        "simplify": simplify,
        "selfDefending": False,  # breaks SVG embed; not worth the cost
        "renameGlobals": False,
        "identifierNamesGenerator": "mangled-shuffled",
    }


def obfuscate(code: str, *, callback_token: str) -> str:
    """Obfuscate *code* deterministically per *callback_token*.

    Raises :class:`ObfuscatorError` if Node fails or returns empty.
    """
    seed = _seed_from_token(callback_token)
    options = _config_from_seed(seed)
    payload = json.dumps({"code": code, "options": options})
    try:
        proc = subprocess.run(
            [_NODE_BIN, str(_HELPER)],
            input=payload, capture_output=True, text=True,
            timeout=_TIMEOUT_S, check=False,
        )
    except FileNotFoundError as e:
        raise ObfuscatorError(f"node binary not found: {_NODE_BIN!r}") from e
    except subprocess.TimeoutExpired as e:
        raise ObfuscatorError("javascript-obfuscator timed out") from e
    if proc.returncode != 0:
        raise ObfuscatorError(
            f"javascript-obfuscator failed rc={proc.returncode} "
            f"stderr={proc.stderr.strip()[:400]}"
        )
    out = proc.stdout
    if not out.strip():
        raise ObfuscatorError("javascript-obfuscator returned empty output")
    return out


def render_fingerprint_js(
    *, callback_token: str, http_base: str, mint_uuid: str,
) -> str:
    """Build the obfuscated fingerprint JS for a single mint.

    Substitutes ``{{BEACON_URL}}`` and ``{{MINT_UUID}}`` in the payload
    template, then runs it through :func:`obfuscate` with a seed
    derived from the callback token.
    """
    template = _PAYLOAD.read_text(encoding="utf-8")
    beacon = f"{http_base.rstrip('/')}/c/{callback_token}"
    src = (
        template
        .replace("{{BEACON_URL}}", beacon)
        .replace("{{MINT_UUID}}", mint_uuid)
    )
    return obfuscate(src, callback_token=callback_token)
