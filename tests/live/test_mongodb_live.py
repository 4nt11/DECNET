import pytest
import pymongo

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestMongoDBLive:
    def test_connect_succeeds(self, live_service):
        port, drain = live_service("mongodb")
        client = pymongo.MongoClient(
            f"mongodb://127.0.0.1:{port}/",
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
        # ismaster is handled — should not raise
        client.admin.command("ismaster")
        client.close()

    def test_connect_logged(self, live_service):
        port, drain = live_service("mongodb")
        client = pymongo.MongoClient(
            f"mongodb://127.0.0.1:{port}/",
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
        try:
            client.admin.command("ismaster")
        except Exception:
            pass
        finally:
            client.close()
        lines = drain()
        assert_rfc5424(lines, service="mongodb", event_type="connect")

    def test_message_logged(self, live_service):
        port, drain = live_service("mongodb")
        client = pymongo.MongoClient(
            f"mongodb://127.0.0.1:{port}/",
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
        try:
            client.admin.command("ismaster")
        except Exception:
            pass
        finally:
            client.close()
        lines = drain()
        assert_rfc5424(lines, service="mongodb", event_type="message")

    def test_list_databases(self, live_service):
        port, drain = live_service("mongodb")
        client = pymongo.MongoClient(
            f"mongodb://127.0.0.1:{port}/",
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
        try:
            # list_database_names triggers OP_MSG
            client.list_database_names()
        except Exception:
            pass
        finally:
            client.close()
        lines = drain()
        # At least one message was exchanged
        assert any("mongodb" in line for line in lines), (
            "Expected at least one mongodb log line"
        )
