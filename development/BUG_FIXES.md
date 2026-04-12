# Bug Fixes — Non-Feature Realism Issues

> These are fingerprint leaks and broken protocol handlers that don't need new
> interaction design — just targeted fixes. All severity High or above from REALISM_AUDIT.md.

---

## 1. HTTP — Werkzeug header leak (High)

### Problem

Every response has two `Server:` headers:
```
Server: Werkzeug/3.1.3 Python/3.11.2
Server: Apache/2.4.54 (Debian)
```

nmap correctly IDs Apache from the second header, but any attacker that does
`curl -I` or runs Burp sees the Werkzeug leak immediately. Port 6443 (K8s) also
leaks Werkzeug in every response.

### Fix — WSGI middleware to strip/replace the header

In `templates/http/server.py` (Flask app), add a `@app.after_request` hook:

```python
@app.after_request
def _fix_server_header(response):
    response.headers["Server"] = os.environ.get("HTTP_SERVER_HEADER", "Apache/2.4.54 (Debian)")
    return response
```

Flask sets `Server: Werkzeug/...` by default. The `after_request` hook runs after
Werkzeug's own header injection, so it overwrites it.

Same fix applies to the K8s server if it's also Flask-based.

### Fix — Apache 403 page body

Current response body: `<h1>403 Forbidden</h1>`

Replace with the actual Apache 2.4 default 403 page:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at {hostname} Port 80</address>
</body></html>
```

Env var `HTTP_SERVER_HEADER` and `NODE_NAME` fill the address line.

### Env vars

| Var | Default |
|-----|---------|
| `HTTP_SERVER_HEADER` | `Apache/2.4.54 (Debian)` |

---

## 2. FTP — Twisted banner (High)

### Problem

```
220 Twisted 25.5.0 FTP Server
```

This is Twisted's built-in FTP server banner. Immediately identifies the framework.

### Fix

Override the banner. The Twisted FTP server class has a `factory.welcomeMessage` or
the protocol's `sendLine()` for the greeting. Simplest fix: subclass the protocol
and override `lineReceived` to intercept the `220` line before it goes out, OR
use a `_FTPFactory` subclass that sets `welcomeMessage`:

```python
from twisted.protocols.ftp import FTPFactory, FTPAnonymousShell
from twisted.internet import reactor
import os

NODE_NAME = os.environ.get("NODE_NAME", "ftpserver")
BANNER = os.environ.get("FTP_BANNER", f"220 (vsFTPd 3.0.3)")

factory = FTPFactory(portal)
factory.welcomeMessage = BANNER   # overrides the Twisted default
```

If `FTPFactory.welcomeMessage` is not directly settable, patch it at class level:

```python
FTPFactory.welcomeMessage = BANNER
```

### Anonymous login + fake directory

The current server rejects everything after login. Fix:

- Use `FTPAnonymousShell` pointed at a `MemoryFilesystem` with fake entries:
  ```
  /
  ├── backup.tar.gz       (0 bytes, but listable)
  ├── db_dump.sql         (0 bytes)
  ├── config.ini          (0 bytes)
  └── credentials.txt     (0 bytes)
  ```
- `RETR` any file → return 1–3 lines of plausible fake content, then close.
- Log every `RETR` with filename and client IP.

### Env vars

| Var | Default |
|-----|---------|
| `FTP_BANNER` | `220 (vsFTPd 3.0.3)` |

---

## 3. MSSQL — Silent on TDS pre-login (High)

### Problem

No response to standard TDS pre-login packets. Connection is dropped silently.
nmap barely recognizes port 1433 (`ms-sql-s?`).

### Diagnosis

The nmap fingerprint shows `\x04\x01\x00\x2b...` which is a valid TDS 7.x pre-login
response fragment. So the server is sending _something_ — but it may be truncated or
malformed enough that nmap can't complete its probe.

Check `templates/mssql/server.py`: look for the raw bytes being sent in response to
`\x12\x01` (TDS pre-login type). Common bugs:
- Wrong packet length field (bytes 2-3 of TDS header)
- Missing `\xff` terminator on the pre-login option list
- Status byte 0x01 instead of 0x00 in the TDS header (signaling last packet)

### Correct TDS 7.x pre-login response structure

```
Byte 0:    0x04        (packet type: tabular result)
Byte 1:    0x01        (status: last packet)
Bytes 2-3: 0x00 0x2b  (total length including header = 43)
Bytes 4-5: 0x00 0x00  (SPID)
Byte 6:    0x01        (packet ID)
Byte 7:    0x00        (window)
--- TDS pre-login payload ---
[VERSION] option: type=0x00, offset=0x001a, length=0x0006
[ENCRYPTION] option: type=0x01, offset=0x0020, length=0x0001
[INSTOPT] option: type=0x02, offset=0x0021, length=0x0001
[THREADID] option: type=0x03, offset=0x0022, length=0x0004
[MARS] option: type=0x04, offset=0x0026, length=0x0001
Terminator: 0xff
VERSION: 0x0e 0x00 0x07 0xd0 0x00 0x00  (14.0.2000 = SQL Server 2017)
ENCRYPTION: 0x02  (ENCRYPT_NOT_SUP)
INSTOPT: 0x00
THREADID: 0x00 0x00 0x00 0x00
MARS: 0x00
```

Verify the current implementation's bytes match this exactly. Fix the length field if off.

---

## 4. MongoDB — Silent on OP_MSG (High)

### Problem

No response to `OP_MSG isMaster` command. nmap shows `mongod?` (partial recognition).

### Diagnosis

MongoDB wire protocol since 3.6 uses `OP_MSG` (opcode 2013). Older clients use
`OP_QUERY` (opcode 2004) against `admin.$cmd`. Check which one `templates/mongodb/server.py`
handles, and whether the response's `responseTo` field matches the request's `requestID`.

Common bugs:
- Handling `OP_QUERY` but not `OP_MSG`
- Wrong `responseTo` in the response header (must echo the request's requestID)
- Missing `flagBits` field in OP_MSG response (must be 0x00000000)

### Correct OP_MSG `hello` response

```python
import struct, bson

def _op_msg_hello_response(request_id: int) -> bytes:
    doc = {
        "ismaster": True,
        "maxBsonObjectSize": 16777216,
        "maxMessageSizeBytes": 48000000,
        "maxWriteBatchSize": 100000,
        "localTime": {"$date": int(time.time() * 1000)},
        "logicalSessionTimeoutMinutes": 30,
        "connectionId": 1,
        "minWireVersion": 0,
        "maxWireVersion": 17,
        "readOnly": False,
        "ok": 1.0,
    }
    payload = b"\x00" + bson.encode(doc)   # section type 0 = body
    flag_bits = struct.pack("<I", 0)
    msg_body = flag_bits + payload
    # MsgHeader: totalLength(4) + requestID(4) + responseTo(4) + opCode(4)
    header = struct.pack("<iiii",
        16 + len(msg_body),   # total length
        1,                     # requestID (server-generated)
        request_id,            # responseTo: echo the client's requestID
        2013,                  # OP_MSG
    )
    return header + msg_body
```

---

## 5. Redis — Empty keyspace (Medium)

### Problem

`KEYS *` returns `*0\r\n` after a successful AUTH. A real exposed Redis always has data.
Attacker does `AUTH anypassword` → `+OK` → `KEYS *` → empty → leaves.

### Fix — fake key-value store

Add a module-level dict with bait data. Handle `KEYS`, `GET`, `SCAN`, `TYPE`, `TTL`:

```python
_FAKE_STORE = {
    b"sessions:user:1234":     b'{"id":1234,"user":"admin","token":"eyJhbGciOiJIUzI1NiJ9..."}',
    b"sessions:user:5678":     b'{"id":5678,"user":"alice","token":"eyJhbGciOiJIUzI1NiJ9..."}',
    b"cache:api_key":          b"sk_live_9mK3xF2aP7qR1bN8cT4dW6vE0yU5hJ",
    b"jwt:secret":             b"super_secret_jwt_signing_key_do_not_share_2024",
    b"user:admin":             b'{"username":"admin","password":"$2b$12$LQv3c1yqBWVHxkd0LHAkC.","role":"superadmin"}',
    b"user:alice":             b'{"username":"alice","password":"$2b$12$XKLDm3vT8nPqR4sY2hE6fO","role":"user"}',
    b"config:db_password":     b"Pr0dDB!2024#Secure",
    b"config:aws_access_key":  b"AKIAIOSFODNN7EXAMPLE",
    b"config:aws_secret_key":  b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    b"rate_limit:192.168.1.1": b"42",
}
```

Commands to handle:
- `KEYS *` → all keys as RESP array
- `KEYS pattern` → filtered (basic glob: `*` matches all, `prefix:*` matches prefix)
- `GET key` → value or `$-1` (nil)
- `SCAN 0` → `*2\r\n$1\r\n0\r\n` + keys array (cursor always 0, return all)
- `TYPE key` → `+string\r\n`
- `TTL key` → `:-1\r\n` (no expiry)

---

## 6. SIP — Hardcoded nonce (Low)

### Problem

`nonce="decnet0000"` is hardcoded. A Shodan signature could detect this string.

### Fix

```python
import secrets
nonce = secrets.token_hex(16)   # e.g. "a3f8c1b2e7d94051..."
```

Generate once per connection in `connection_made`. The WWW-Authenticate header
becomes: `Digest realm="{NODE_NAME}", nonce="{nonce}", algorithm=MD5`

---

## 7. VNC — Hardcoded DES challenge (Low)

### Problem

The 16-byte DES challenge sent during VNC auth negotiation is static.

### Fix

```python
import os
self._vnc_challenge = os.urandom(16)
```

Generate in `connection_made`. Send `self._vnc_challenge` in the Security handshake.

---

## 8. PostgreSQL — Hardcoded salt (Low)

### Problem

`AuthenticationMD5Password` response contains `\xde\xad\xbe\xef` as the 4-byte salt.

### Fix

```python
import os
self._pg_salt = os.urandom(4)
```

Use `self._pg_salt` in the `R\x00\x00\x00\x0c\x00\x00\x00\x05` response bytes.

---

## Files to change

| File | Change |
|------|--------|
| `templates/http/server.py` | `after_request` header fix, proper 403 body |
| `templates/ftp/server.py` | Banner override, anonymous login, fake dir |
| `templates/mssql/server.py` | Fix TDS pre-login response bytes |
| `templates/mongodb/server.py` | Add OP_MSG handler, fix responseTo |
| `templates/redis/server.py` | Add fake key-value store, KEYS/GET/SCAN |
| `templates/sip/server.py` | Random nonce per connection |
| `templates/vnc/server.py` | Random DES challenge per connection |
| `templates/postgres/server.py` | Random MD5 salt per connection |
| `tests/test_http_headers.py` | New: assert single Server header, correct 403 body |
| `tests/test_redis.py` | Extend: KEYS *, GET, SCAN return bait data |

---

## Priority order

1. HTTP header leak — immediately visible to any attacker
2. FTP banner — immediate framework disclosure
3. MSSQL silent — service appears dead
4. MongoDB silent — service appears dead
5. Redis empty keyspace — breaks the bait value proposition
6. SIP/VNC/PostgreSQL hardcoded values — low risk, quick wins
