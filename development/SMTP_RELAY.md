# SMTP Open Relay — Plan

> Priority: **P0** — DATA handler is broken (502 on every body line).
> Scenario: attacker finds open relay, sends mail through it.

---

## What's broken today

`templates/smtp/server.py` sends `354 End data with <CR><LF>.<CR><LF>` on `DATA`, then
falls back to `_handle_line()` for every subsequent line. Because those lines don't start
with a recognized SMTP verb, every line gets:

```
502 5.5.2 Error: command not recognized
```

The session never completes. The message is silently dropped.

---

## Fix: DATA state machine

Add a `_in_data` flag. Once `DATA` is received, accumulate raw body lines until the
terminator `\r\n.\r\n`. On terminator: log the message, return `250`, flip flag back.

### State variables added to `SMTPProtocol.__init__`

```python
self._in_data   = False
self._data_buf  = []   # accumulate body lines
self._mail_from = ""
self._rcpt_to   = []
```

### Modified `data_received`

No change — still splits on `\r\n`.

### Modified `_handle_line`

```python
def _handle_line(self, line: str) -> None:
    # DATA body accumulation mode
    if self._in_data:
        if line == ".":
            # end of message
            body = "\r\n".join(self._data_buf)
            msg_id = _rand_msg_id()
            _log("message_accepted",
                 src=self._peer[0],
                 mail_from=self._mail_from,
                 rcpt_to=",".join(self._rcpt_to),
                 body_bytes=len(body),
                 msg_id=msg_id)
            self._transport.write(f"250 2.0.0 Ok: queued as {msg_id}\r\n".encode())
            self._in_data  = False
            self._data_buf = []
        else:
            # RFC 5321 dot-stuffing: leading dot means literal dot, strip it
            self._data_buf.append(line[1:] if line.startswith("..") else line)
        return

    cmd = line.split()[0].upper() if line.split() else ""
    # ... existing handlers ...
    elif cmd == "MAIL":
        self._mail_from = line.split(":", 1)[1].strip() if ":" in line else line
        _log("mail_from", src=self._peer[0], value=self._mail_from)
        self._transport.write(b"250 2.0.0 Ok\r\n")
    elif cmd == "RCPT":
        rcpt = line.split(":", 1)[1].strip() if ":" in line else line
        self._rcpt_to.append(rcpt)
        _log("rcpt_to", src=self._peer[0], value=rcpt)
        self._transport.write(b"250 2.1.5 Ok\r\n")
    elif cmd == "DATA":
        if not self._mail_from or not self._rcpt_to:
            self._transport.write(b"503 5.5.1 Error: need MAIL command\r\n")
        else:
            self._in_data = True
            self._transport.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    elif cmd == "RSET":
        self._mail_from = ""
        self._rcpt_to   = []
        self._in_data   = False
        self._data_buf  = []
        self._transport.write(b"250 2.0.0 Ok\r\n")
```

### Helper

```python
import random, string

def _rand_msg_id() -> str:
    """Return a Postfix-style 12-char hex queue ID."""
    return "".join(random.choices("0123456789ABCDEF", k=12))
```

---

## Open relay behavior

The current server already returns `250 2.1.5 Ok` for any `RCPT TO` regardless of domain.
That's correct — do NOT gate on the domain. The attacker's goal is to relay spam. We let
them "succeed" and log everything.

Remove the `AUTH` rejection + close. An open relay doesn't require authentication. Replace:

```python
elif cmd == "AUTH":
    _log("auth_attempt", src=self._peer[0], command=line)
    self._transport.write(b"535 5.7.8 Error: authentication failed: ...\r\n")
    self._transport.close()
```

With:

```python
elif cmd == "AUTH":
    # Log the attempt but advertise that auth succeeds (open relay bait)
    _log("auth_attempt", src=self._peer[0], command=line)
    self._transport.write(b"235 2.7.0 Authentication successful\r\n")
```

Some scanners probe AUTH before DATA. Accepting it keeps them engaged.

---

## Banner / persona

Current banner is already perfect: `220 omega-decky ESMTP Postfix (Debian/GNU)`.

The `SMTP_BANNER` env var lets per-decky customization happen at deploy time via the
persona config — no code change needed.

---

## Log events emitted

| event_type       | Fields                                            |
|------------------|---------------------------------------------------|
| `connect`        | src, src_port                                     |
| `ehlo`           | src, domain                                       |
| `auth_attempt`   | src, command                                      |
| `mail_from`      | src, value                                        |
| `rcpt_to`        | src, value (one event per recipient)              |
| `message_accepted` | src, mail_from, rcpt_to, body_bytes, msg_id    |
| `disconnect`     | src                                               |

---

## Files to change

| File | Change |
|------|--------|
| `templates/smtp/server.py` | DATA state machine, open relay AUTH accept, RSET fix |
| `tests/test_smtp.py` | New: DATA → 250 flow, multi-recipient, dot-stuffing, RSET |

---

## Test cases (pytest)

```python
# full send flow
conn → EHLO → MAIL FROM → RCPT TO → DATA → body lines → "." → 250 2.0.0 Ok: queued as ...

# multi-recipient
RCPT TO x3 → DATA → body → "." → 250

# dot-stuffing
..real dot → body line stored as ".real dot"

# RSET mid-session
MAIL FROM → RCPT TO → RSET → assert _mail_from == "" and _rcpt_to == []

# AUTH accept
AUTH PLAIN base64 → 235

# 503 if DATA before MAIL
DATA (no prior MAIL) → 503
```

---

## Verification against live decky

```bash
# Full relay test
printf "EHLO test.com\r\nMAIL FROM:<hacker@evil.com>\r\nRCPT TO:<admin@target.com>\r\nDATA\r\nSubject: hello\r\n\r\nBody line 1\r\nBody line 2\r\n.\r\nQUIT\r\n" | nc 192.168.1.200 25

# Expected final lines:
# 354 End data with ...
# 250 2.0.0 Ok: queued as <ID>
# 221 2.0.0 Bye
```
