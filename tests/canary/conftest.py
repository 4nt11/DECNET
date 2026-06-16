# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared fixtures for canary tests — minimal DOCX/XLSX/HTML/PDF fixtures.

We synthesise the OOXML zips inline rather than checking real binary
fixtures into the repo.  Keeps the test surface portable and the diff
reviewable; the smallest valid DOCX is ~12 files but Word/LibreOffice
both accept a stripped-down skeleton with just ``[Content_Types].xml``,
``_rels/.rels``, ``word/document.xml``, and ``word/_rels/document.xml.rels``.
"""
from __future__ import annotations

import io
import os
import zipfile

import pytest


@pytest.fixture(autouse=True, scope="session")
def _canary_fingerprint_secret():
    """Ensure DECNET_CANARY_FINGERPRINT_SECRET is set for all canary tests.

    Fingerprint generators call nonce_for() which raises if the env var
    is unset. A test-only sentinel value is fine — it just needs to exist.
    """
    key = "DECNET_CANARY_FINGERPRINT_SECRET"
    prev = os.environ.get(key)
    os.environ.setdefault(key, "test-secret-for-canary-tests-only")
    yield
    if prev is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = prev


_DOCX_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>'
)

_DOCX_PACKAGE_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    '</Relationships>'
)

_DOCX_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>Existing content.</w:t></w:r></w:p></w:body>'
    '</w:document>'
)

_DOCX_DOCUMENT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '</Relationships>'
)


@pytest.fixture
def minimal_docx() -> bytes:
    """Return a tiny but structurally valid DOCX as bytes."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _DOCX_CONTENT_TYPES)
        zf.writestr("_rels/.rels", _DOCX_PACKAGE_RELS)
        zf.writestr("word/document.xml", _DOCX_DOCUMENT)
        zf.writestr("word/_rels/document.xml.rels", _DOCX_DOCUMENT_RELS)
    return out.getvalue()


_XLSX_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Override PartName="/xl/workbook.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '</Types>'
)

_XLSX_WORKBOOK_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '</Relationships>'
)


@pytest.fixture
def minimal_xlsx() -> bytes:
    """Return a tiny but structurally valid XLSX as bytes."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _XLSX_CONTENT_TYPES)
        zf.writestr("_rels/.rels", _DOCX_PACKAGE_RELS.replace("word/document.xml", "xl/workbook.xml"))
        zf.writestr("xl/workbook.xml", '<workbook/>')
        zf.writestr("xl/_rels/workbook.xml.rels", _XLSX_WORKBOOK_RELS)
    return out.getvalue()
