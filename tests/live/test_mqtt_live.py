import time

import pytest
import paho.mqtt.client as mqtt

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestMQTTLive:
    def test_connect_accepted(self, live_service):
        port, drain = live_service("mqtt")
        connected = []
        client = mqtt.Client(client_id="test-scanner")
        client.on_connect = lambda c, u, f, rc: connected.append(rc)
        client.connect("127.0.0.1", port, keepalive=5)
        client.loop_start()
        deadline = time.monotonic() + 5
        while not connected and time.monotonic() < deadline:
            time.sleep(0.05)
        client.loop_stop()
        client.disconnect()
        assert connected and connected[0] == 0, f"Expected CONNACK rc=0, got {connected}"

    def test_connect_logged(self, live_service):
        port, drain = live_service("mqtt")
        client = mqtt.Client(client_id="hax0r")
        client.connect("127.0.0.1", port, keepalive=5)
        client.loop_start()
        time.sleep(0.3)
        client.loop_stop()
        client.disconnect()
        lines = drain()
        assert_rfc5424(lines, service="mqtt", event_type="auth")

    def test_client_id_in_log(self, live_service):
        port, drain = live_service("mqtt")
        client = mqtt.Client(client_id="evil-scanner-9000")
        client.connect("127.0.0.1", port, keepalive=5)
        client.loop_start()
        time.sleep(0.3)
        client.loop_stop()
        client.disconnect()
        lines = drain()
        matched = assert_rfc5424(lines, service="mqtt", event_type="auth")
        assert "evil-scanner-9000" in matched, (
            f"Expected client_id in log line. Got:\n{matched!r}"
        )

    def test_subscribe_logged(self, live_service):
        port, drain = live_service("mqtt")
        subscribed = []
        client = mqtt.Client(client_id="sub-test")
        client.on_subscribe = lambda c, u, mid, qos: subscribed.append(mid)
        client.connect("127.0.0.1", port, keepalive=5)
        client.loop_start()
        time.sleep(0.2)
        client.subscribe("plant/#")
        time.sleep(0.3)
        client.loop_stop()
        client.disconnect()
        lines = drain()
        assert_rfc5424(lines, service="mqtt", event_type="subscribe")
