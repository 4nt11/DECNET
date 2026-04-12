import pytest
import requests

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestHTTPLive:
    def test_get_request_logged(self, live_service):
        port, drain = live_service("http")
        resp = requests.get(f"http://127.0.0.1:{port}/admin", timeout=5)
        assert resp.status_code == 403
        lines = drain()
        assert_rfc5424(lines, service="http", event_type="request")

    def test_server_header_set(self, live_service):
        port, drain = live_service("http")
        resp = requests.get(f"http://127.0.0.1:{port}/", timeout=5)
        assert "Server" in resp.headers
        assert resp.headers["Server"] != ""

    def test_post_body_logged(self, live_service):
        port, drain = live_service("http")
        requests.post(
            f"http://127.0.0.1:{port}/login",
            data={"username": "admin", "password": "secret"},
            timeout=5,
        )
        lines = drain()
        # body field present in log line
        assert any("body=" in l for l in lines if "request" in l), (
            f"Expected 'body=' in request log line. Got:\n" + "\n".join(lines[:10])
        )

    def test_method_and_path_in_log(self, live_service):
        port, drain = live_service("http")
        requests.get(f"http://127.0.0.1:{port}/secret/file.txt", timeout=5)
        lines = drain()
        matched = assert_rfc5424(lines, service="http", event_type="request")
        assert "GET" in matched or 'method="GET"' in matched
        assert "/secret/file.txt" in matched or 'path="/secret/file.txt"' in matched
