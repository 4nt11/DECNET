"""
Schemathesis contract tests.

Generates requests from the OpenAPI spec and verifies that no input causes a 5xx.

Currently scoped to `not_a_server_error` only — full response-schema conformance
(including undocumented 401 responses) is blocked by DEBT-020 (missing error
response declarations across all protected endpoints). Once DEBT-020 is resolved,
replace the checks list with the default (remove the argument) for full compliance.

Requires DECNET_DEVELOPER=true (set in tests/conftest.py) to expose /openapi.json.
"""
import schemathesis
from schemathesis.checks import not_a_server_error
from decnet.web.api import app

schema = schemathesis.openapi.from_asgi("/openapi.json", app)


@schemathesis.pytest.parametrize(api=schema)
def test_schema_compliance(case):
    case.call_and_validate(checks=[not_a_server_error])
