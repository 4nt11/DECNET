# SPDX-License-Identifier: AGPL-3.0-or-later
import ftplib

import pytest

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestFTPLive:
    def test_banner_received(self, live_service):
        port, drain = live_service("ftp")
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", port, timeout=5)
        welcome = ftp.getwelcome()
        ftp.close()
        assert "220" in welcome or "vsFTPd" in welcome or len(welcome) > 0

    def test_login_logged(self, live_service):
        port, drain = live_service("ftp")
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", port, timeout=5)
        try:
            ftp.login("admin", "hunter2")
        except ftplib.all_errors:
            pass
        finally:
            ftp.close()
        lines = drain()
        assert_rfc5424(lines, service="ftp")

    def test_connect_logged(self, live_service):
        port, drain = live_service("ftp")
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", port, timeout=5)
        ftp.close()
        lines = drain()
        # At least one RFC 5424 line from the ftp service
        rfc_lines = [line for line in lines if "<" in line and ">1 " in line and "ftp" in line]
        assert rfc_lines, "No ftp RFC 5424 lines found. stdout:\n" + "\n".join(lines[:15])
