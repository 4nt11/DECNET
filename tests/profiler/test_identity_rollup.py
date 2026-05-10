"""Tests for ``decnet.profiler.identity_rollup.extract_fp_summaries``.

Pure unit tests against the production bounty shape that
``decnet.profiler.worker._build_record`` writes into
``Attacker.fingerprints`` — a list of ``{bounty_type, payload, ...}``
dicts where the meaningful data lives under ``payload.fingerprint_type``.
"""

from __future__ import annotations

import json

from decnet.profiler.identity_rollup import extract_fp_summaries


def _bounty(fp_type: str, **payload_extras) -> dict:
    """Build a bounty dict shaped the way the profiler writes it."""
    return {
        "bounty_type": "fingerprint",
        "payload": {"fingerprint_type": fp_type, **payload_extras},
    }


def _row_with(*entries) -> dict:
    return {"fingerprints": json.dumps(list(entries))}


class TestExtractFpSummaries:

    def test_empty_input_returns_all_none(self):
        result = extract_fp_summaries([])
        assert all(v is None for v in result.values())
        assert "ja3_hashes" in result
        assert "hassh_hashes" in result
        assert "tls_cert_sha256" in result
        assert "ja4h_hashes" in result
        assert "ja4_quic_hashes" in result

    def test_single_row_single_cert(self):
        row = _row_with(_bounty("tls_certificate", cert_sha256="ab" * 32))
        result = extract_fp_summaries([row])
        assert result["ja3_hashes"] is None
        assert result["hassh_hashes"] is None
        assert json.loads(result["tls_cert_sha256"]) == ["ab" * 32]

    def test_dedupe_across_rows(self):
        sha = "ab" * 32
        a = _row_with(_bounty("tls_certificate", cert_sha256=sha))
        b = _row_with(_bounty("tls_certificate", cert_sha256=sha))
        result = extract_fp_summaries([a, b])
        assert json.loads(result["tls_cert_sha256"]) == [sha]

    def test_sorted_output_is_deterministic(self):
        a = _row_with(
            _bounty("tls_certificate", cert_sha256="ff" * 32),
            _bounty("tls_certificate", cert_sha256="11" * 32),
            _bounty("tls_certificate", cert_sha256="aa" * 32),
        )
        result = extract_fp_summaries([a])
        # Same input twice must produce byte-identical output.
        assert result == extract_fp_summaries([a])
        assert json.loads(result["tls_cert_sha256"]) == sorted(
            ["ff" * 32, "11" * 32, "aa" * 32]
        )

    def test_all_three_families_at_once(self):
        row = _row_with(
            _bounty("ja3", ja3="ja3-abc"),
            _bounty("hassh_server", hash="hassh-def"),
            _bounty("tls_certificate", cert_sha256="ab" * 32),
        )
        result = extract_fp_summaries([row])
        assert json.loads(result["ja3_hashes"]) == ["ja3-abc"]
        assert json.loads(result["hassh_hashes"]) == ["hassh-def"]
        assert json.loads(result["tls_cert_sha256"]) == ["ab" * 32]

    def test_unknown_fingerprint_type_ignored(self):
        # tcpfp / ja4l / http_quirks have no rollup column yet; they
        # must not pollute the three families that do.
        row = _row_with(
            _bounty("tcpfp", hash="tcpfp-x"),
            _bounty("ja4l", ja4l="ja4l-y"),
            _bounty("http_quirks", quirks="..."),
        )
        result = extract_fp_summaries([row])
        assert result["ja3_hashes"] is None
        assert result["hassh_hashes"] is None
        assert result["tls_cert_sha256"] is None

    def test_missing_payload_key_skipped(self):
        # tls_certificate bounty shaped like a sniffer-only payload
        # (no cert_sha256). Must not crash, must not record an entry.
        row = _row_with({
            "bounty_type": "fingerprint",
            "payload": {"fingerprint_type": "tls_certificate", "subject_cn": "x"},
        })
        result = extract_fp_summaries([row])
        assert result["tls_cert_sha256"] is None

    def test_malformed_fingerprints_json_returns_all_none(self):
        result = extract_fp_summaries([{"fingerprints": "not json"}])
        assert all(v is None for v in result.values())

    def test_missing_fingerprints_field_returns_all_none(self):
        result = extract_fp_summaries([{"some_other_field": True}])
        assert all(v is None for v in result.values())

    def test_payload_as_string_is_json_decoded(self):
        # Defensive: some legacy storage may have nested-stringified payloads.
        row = {
            "fingerprints": json.dumps([{
                "bounty_type": "fingerprint",
                "payload": json.dumps({
                    "fingerprint_type": "tls_certificate",
                    "cert_sha256": "cd" * 32,
                }),
            }]),
        }
        result = extract_fp_summaries([row])
        assert json.loads(result["tls_cert_sha256"]) == ["cd" * 32]

    def test_non_string_hash_values_skipped(self):
        row = _row_with({
            "bounty_type": "fingerprint",
            "payload": {"fingerprint_type": "tls_certificate", "cert_sha256": 12345},
        })
        result = extract_fp_summaries([row])
        assert result["tls_cert_sha256"] is None

    def test_dedup_across_many_rows_with_overlap(self):
        rows = [
            _row_with(_bounty("ja3", ja3="ja3-shared")),
            _row_with(
                _bounty("ja3", ja3="ja3-shared"),
                _bounty("ja3", ja3="ja3-second"),
            ),
            _row_with(_bounty("ja3", ja3="ja3-third")),
        ]
        result = extract_fp_summaries(rows)
        assert json.loads(result["ja3_hashes"]) == sorted(
            ["ja3-shared", "ja3-second", "ja3-third"]
        )

    # ── ja4h + ja4_quic (PR2 columns) ────────────────────────────────

    def test_ja4h_single_value(self):
        row = _row_with(_bounty("ja4h", ja4h="GE11nn0000_02_abc_000"))
        result = extract_fp_summaries([row])
        assert json.loads(result["ja4h_hashes"]) == ["GE11nn0000_02_abc_000"]

    def test_ja4_quic_single_value(self):
        row = _row_with(_bounty("ja4_quic", ja4_quic="q13d0310h2_002f_0403_h3"))
        result = extract_fp_summaries([row])
        assert json.loads(result["ja4_quic_hashes"]) == ["q13d0310h2_002f_0403_h3"]

    def test_ja4h_dedup_across_rows(self):
        a = _row_with(_bounty("ja4h", ja4h="GE11nn0000_02_abc_000"))
        b = _row_with(_bounty("ja4h", ja4h="GE11nn0000_02_abc_000"))
        c = _row_with(_bounty("ja4h", ja4h="GE20nn0000_04_def_000"))
        result = extract_fp_summaries([a, b, c])
        hashes = json.loads(result["ja4h_hashes"])
        assert len(hashes) == 2
        assert "GE11nn0000_02_abc_000" in hashes
        assert "GE20nn0000_04_def_000" in hashes

    def test_ja4h_and_ja4_quic_coexist(self):
        row = _row_with(
            _bounty("ja4h", ja4h="GE11nn0000_02_abc_000"),
            _bounty("ja4_quic", ja4_quic="q13d0310h2_002f_0403_h3"),
        )
        result = extract_fp_summaries([row])
        assert json.loads(result["ja4h_hashes"]) == ["GE11nn0000_02_abc_000"]
        assert json.loads(result["ja4_quic_hashes"]) == ["q13d0310h2_002f_0403_h3"]

    def test_ja4h_missing_payload_key_skipped(self):
        # bounty shaped like a fingerprint but missing the 'ja4h' key
        row = _row_with({
            "bounty_type": "fingerprint",
            "payload": {"fingerprint_type": "ja4h", "protocol": "h1"},
        })
        result = extract_fp_summaries([row])
        assert result["ja4h_hashes"] is None

    def test_empty_returns_none_for_new_columns(self):
        result = extract_fp_summaries([])
        assert "ja4h_hashes" in result
        assert result["ja4h_hashes"] is None
        assert "ja4_quic_hashes" in result
        assert result["ja4_quic_hashes"] is None
