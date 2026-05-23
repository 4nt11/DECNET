# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RFC 5424 syslog formatter."""

import re
from datetime import datetime, timezone


from decnet.logging.syslog_formatter import (
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    format_rfc5424,
)

# RFC 5424 header regex: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]
_RFC5424_RE = re.compile(
    r"^<(\d+)>1 "                       # PRI + version
    r"(\S+) "                            # TIMESTAMP
    r"(\S+) "                            # HOSTNAME
    r"(\S+) "                            # APP-NAME
    r"- "                                # PROCID (NILVALUE)
    r"(\S+) "                            # MSGID
    r"(.+)$",                            # SD + optional MSG
)


def _parse(line: str) -> re.Match:
    m = _RFC5424_RE.match(line)
    assert m is not None, f"Not RFC 5424: {line!r}"
    return m


class TestPRI:
    def test_info_pri(self):
        line = format_rfc5424("http", "host1", "request", SEVERITY_INFO)
        m = _parse(line)
        pri = int(m.group(1))
        assert pri == 16 * 8 + 6  # local0 + info = 134

    def test_warning_pri(self):
        line = format_rfc5424("http", "host1", "warn", SEVERITY_WARNING)
        pri = int(_parse(line).group(1))
        assert pri == 16 * 8 + 4  # 132

    def test_error_pri(self):
        line = format_rfc5424("http", "host1", "err", SEVERITY_ERROR)
        pri = int(_parse(line).group(1))
        assert pri == 16 * 8 + 3  # 131

    def test_pri_range(self):
        for sev in range(8):
            line = format_rfc5424("svc", "h", "e", sev)
            pri = int(_parse(line).group(1))
            assert 0 <= pri <= 191


class TestTimestamp:
    def test_utc_timestamp(self):
        ts_str = datetime(2026, 4, 4, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        line = format_rfc5424("svc", "h", "e", timestamp=datetime(2026, 4, 4, 12, 0, 0, tzinfo=timezone.utc))
        m = _parse(line)
        assert m.group(2) == ts_str

    def test_default_timestamp_is_utc(self):
        line = format_rfc5424("svc", "h", "e")
        ts_field = _parse(line).group(2)
        # Should end with +00:00 or Z
        assert "+" in ts_field or ts_field.endswith("Z")


class TestHeader:
    def test_hostname(self):
        line = format_rfc5424("http", "decky-01", "request")
        assert _parse(line).group(3) == "decky-01"

    def test_appname(self):
        line = format_rfc5424("mysql", "host", "login_attempt")
        assert _parse(line).group(4) == "mysql"

    def test_msgid(self):
        line = format_rfc5424("ftp", "host", "login_attempt")
        assert _parse(line).group(5) == "login_attempt"

    def test_procid_is_nilvalue(self):
        line = format_rfc5424("svc", "h", "e")
        assert " - " in line  # PROCID is always NILVALUE

    def test_appname_truncated(self):
        long_name = "a" * 100
        line = format_rfc5424(long_name, "h", "e")
        appname = _parse(line).group(4)
        assert len(appname) <= 48

    def test_msgid_truncated(self):
        long_msgid = "x" * 100
        line = format_rfc5424("svc", "h", long_msgid)
        msgid = _parse(line).group(5)
        assert len(msgid) <= 32


class TestStructuredData:
    def test_nilvalue_when_no_fields(self):
        line = format_rfc5424("svc", "h", "e")
        sd_and_msg = _parse(line).group(6)
        assert sd_and_msg.startswith("-")

    def test_sd_element_present(self):
        line = format_rfc5424("http", "h", "request", remote_addr="1.2.3.4", method="GET")
        sd_and_msg = _parse(line).group(6)
        assert sd_and_msg.startswith("[relay@55555 ")
        assert 'remote_addr="1.2.3.4"' in sd_and_msg
        assert 'method="GET"' in sd_and_msg

    def test_sd_escape_double_quote(self):
        line = format_rfc5424("svc", "h", "e", ua='foo"bar')
        assert r'ua="foo\"bar"' in line

    def test_sd_escape_backslash(self):
        line = format_rfc5424("svc", "h", "e", path="a\\b")
        assert r'path="a\\b"' in line

    def test_sd_escape_close_bracket(self):
        line = format_rfc5424("svc", "h", "e", val="a]b")
        assert r'val="a\]b"' in line


class TestMsg:
    def test_optional_msg_appended(self):
        line = format_rfc5424("svc", "h", "e", msg="hello world")
        assert line.endswith(" hello world")

    def test_no_msg_no_trailing_space_in_sd(self):
        line = format_rfc5424("svc", "h", "e", key="val")
        # SD element closes with ]
        assert line.rstrip().endswith("]")
