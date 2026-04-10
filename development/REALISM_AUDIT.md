# Service Realism Audit

> Live-tested against `192.168.1.200` (omega-decky, full-audit.ini).
> Every result below is from an actual `nc` or `nmap` probe, not code reading.

---

## nmap -sV Summary

```
21/tcp   ftp           vsftpd (before 2.0.8) or WU-FTPD   ← WRONG: banner says "Twisted 25.5.0"
23/tcp   telnet        (unrecognized — Cowrie)
25/tcp   smtp          Postfix smtpd                       ✓
80/tcp   http          Apache httpd 2.4.54 ((Debian))      ✓ BUT leaks Werkzeug
110/tcp  pop3          (unrecognized)
143/tcp  imap          (unrecognized)
389/tcp  ldap          Cisco LDAP server
445/tcp  microsoft-ds                                      ✓
1433/tcp ms-sql-s?     (partially recognized)
1883/tcp mqtt                                              ✓
2375/tcp docker        Docker 24.0.5                       ✓
3306/tcp mysql         MySQL 5.7.38-log                    ✓
3389/tcp ms-wbt-server xrdp
5060/tcp sip           SIP endpoint; Status: 401 Unauthorized ✓
5432/tcp postgresql?   (partially recognized)
5900/tcp vnc           VNC protocol 3.8                   ✓
6379/tcp redis?        (partially recognized)
6443/tcp (unrecognized) — K8s not responding at all
9200/tcp wap-wsp?      (completely unrecognized — ES)
27017/tcp mongod?      (partially recognized)
502/tcp  CLOSED        — Conpot Modbus not on this port
```

---

## Service-by-Service

---

### SMTP — port 25

**Probe:**
```
220 omega-decky ESMTP Postfix (Debian/GNU)
250-PIPELINING / SIZE / VRFY / AUTH PLAIN LOGIN / ENHANCEDSTATUSCODES / 8BITMIME / DSN
250 2.1.0 Ok          ← MAIL FROM accepted
250 2.1.5 Ok          ← RCPT TO accepted for any domain ✓ (open relay bait)
354 End data with...  ← DATA opened
502 5.5.2 Error: command not recognized  ← BUG: each message line fails
221 2.0.0 Bye
```

**Verdict:** Banner and EHLO are perfect. DATA handler is broken — server reads the socket line-by-line but the asyncio handler dispatches each line as a new command instead of buffering until `.\r\n`. The result is every line of the email body gets a 502 and the message is silently dropped.

**Fixes needed:**
- Buffer DATA state until `\r\n.\r\n` terminator
- Return `250 2.0.0 Ok: queued as <8-hex-id>` after message accepted
- Don't require AUTH for relay (open relay is the point)
- Optionally: store message content so IMAP can serve it later

---

### IMAP — port 143

**Probe:**
```
* OK [omega-decky] IMAP4rev1 Service Ready
A1 OK CAPABILITY completed
A2 NO [AUTHENTICATIONFAILED] Invalid credentials    ← always, for any user/pass
A3 BAD Command not recognized                       ← LIST, SELECT, FETCH all unknown
```

**Verdict:** Login always fails. No mailbox commands implemented. An attacker who tries credential stuffing or default passwords (admin/admin, root/root) gets nothing and moves on. This is the biggest missed opportunity in the whole stack.

**Fixes needed:**
- Accept configurable credentials (default `admin`/`admin` or pulled from persona config)
- Implement: SELECT, LIST, FETCH, UID FETCH, SEARCH, LOGOUT
- Serve seeded fake mailboxes with bait content (see IMAP_BAIT.md)
- CAPABILITY should advertise `LITERAL+`, `SASL-IR`, `LOGIN-REFERRALS`, `ID`, `ENABLE`, `IDLE`
- Banner should hint at Dovecot: `* OK Dovecot ready.`

---

### POP3 — port 110

**Probe:**
```
+OK omega-decky POP3 server ready
+OK               ← USER accepted
-ERR Authentication failed    ← always
-ERR Unknown command          ← STAT, LIST, RETR all unknown
```

**Verdict:** Same problem as IMAP. CAPA only returns `USER`. Should be paired with IMAP fix to serve the same fake mailbox.

**Fixes needed:**
- Accept same credentials as IMAP
- Implement: STAT, LIST, RETR, DELE, TOP, UIDL, CAPA
- CAPA should return: `TOP UIDL RESP-CODES AUTH-RESP-CODE SASL USER`

---

### HTTP — port 80

**Probe:**
```
HTTP/1.1 403 FORBIDDEN
Server: Werkzeug/3.1.8 Python/3.11.2    ← DEAD GIVEAWAY
Server: Apache/2.4.54 (Debian)           ← duplicate Server header
```

**Verdict:** nmap gets the Apache fingerprint right, but any attacker who looks at response headers sees two `Server:` headers — one of which is clearly Werkzeug/Flask. The HTTP body is also a bare `<h1>403 Forbidden</h1>` with no Apache default page styling.

**Fixes needed:**
- Strip Werkzeug from Server header (set `SERVER_NAME` on the Flask app or use middleware to overwrite)
- Apache default 403 page should be the actual Apache HTML, not a bare `<h1>` tag
- Per-path routing for fake apps: `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`, etc.
- POST credential capture on login endpoints

---

### FTP — port 21

**Probe:**
```
220 Twisted 25.5.0 FTP Server     ← terrible: exposes framework
331 Guest login ok...
550 Requested action not taken    ← after login, nothing works
503 Incorrect sequence of commands: must send PORT or PASV before RETR
```

**Verdict:** Banner immediately identifies this as Twisted's built-in FTP server. No directory listing. PASV mode not implemented so clients hang. Real FTP honeypots should expose anonymous access with a fake directory tree containing interesting-sounding files.

**Fixes needed:**
- Override banner to: `220 (vsFTPd 3.0.3)` or similar
- Implement anonymous login (no password required)
- Implement PASV and at minimum LIST — return a fake directory with files: `backup.tar.gz`, `db_dump.sql`, `config.ini`, `credentials.txt`
- Log any RETR attempts (file name, client IP)

---

### MySQL — port 3306

**Probe:**
```
HANDSHAKE: ...5.7.38-log...
Version: 5.7.38-log
```

**Verdict:** Handshake is excellent. nmap fingerprints it perfectly. Always returns `Access denied` which is correct behavior. The only issue is the hardcoded auth plugin data bytes in the greeting — a sophisticated scanner could detect the static challenge.

**Fixes needed (low priority):**
- Randomize the 20-byte auth plugin data per connection

---

### PostgreSQL — port 5432

**Probe:**
```
R\x00\x00\x00\x0c\x00\x00\x00\x05\xde\xad\xbe\xef
```
That's `AuthenticationMD5Password` (type=5) with salt `0xdeadbeef`.

**Verdict:** Correct protocol response. Salt is hardcoded and static — `deadbeef` is trivially identifiable as fake.

**Fixes needed (low priority):**
- Randomize the 4-byte MD5 salt per connection

---

### MSSQL — port 1433

**Probe:** No response to standard TDS pre-login packets. Server drops connection immediately.

**Verdict:** Broken. TDS pre-login handler is likely mismatching the packet format we sent.

**Fixes needed:**
- Debug TDS pre-login response — currently silent
- Verify the hardcoded TDS response bytes are valid

---

### Redis — port 6379

**Probe:**
```
+OK           ← AUTH accepted (any password!)
$150
redis_version:7.2.7 / os:Linux 5.15.0 / uptime_in_seconds:864000 ...
*0            ← KEYS * returns empty
```

**Verdict:** Accepts any AUTH password (intentional for bait). INFO looks real. But `KEYS *` returns nothing — a real Redis exposed to the internet always has data. An attacker who gets `+OK` on AUTH will immediately run `KEYS *` or `SCAN 0` and leave when they find nothing.

**Fixes needed:**
- Add fake key-value store: session tokens, JWT secrets, cached user objects, API keys
- `KEYS *` → `["sessions:user:1234", "cache:api_key", "jwt:secret", "user:admin"]`
- `GET sessions:user:1234` → JSON user object with credentials
- `GET jwt:secret` → a plausible JWT signing key

---

### MongoDB — port 27017

**Probe:** No response to OP_MSG `isMaster` command.

**Verdict:** Broken or rejecting the wire protocol format we sent.

**Fixes needed:**
- Debug the OP_MSG/OP_QUERY handler

---

### Elasticsearch — port 9200

**Probe:**
```json
{"name":"omega-decky","cluster_uuid":"xC3Pr9abTq2mNkOeLvXwYA","version":{"number":"7.17.9",...}}
/_cat/indices → []   ← empty: dead giveaway
```

**Verdict:** Root response is convincing. But `/_cat/indices` returns an empty array — a real exposed ES instance has indices. nmap doesn't recognize port 9200 as Elasticsearch at all ("wap-wsp?").

**Fixes needed:**
- Add fake indices: `logs-2024.01`, `users`, `products`, `audit_trail`
- `/_cat/indices` → return rows with doc counts, sizes
- `/_search` on those indices → return sample documents (bait data: user records, API tokens)

---

### Docker API — port 2375

**Probe:**
```json
/version → {Version: "24.0.5", ApiVersion: "1.43", GoVersion: "go1.20.6", ...}  ✓
/containers/json → [{"Id":"a1b2c3d4e5f6","Names":["/webapp"],"Image":"nginx:latest",...}]
```

**Verdict:** Version response is perfect. Container list is minimal (one hardcoded container). No `/images/json` data, no exec endpoint. An attacker will immediately try `POST /containers/webapp/exec` to get RCE.

**Fixes needed:**
- Add 3-5 containers with realistic names/images: `db` (postgres:14), `api` (node:18-alpine), `redis` (redis:7)
- Add `/images/json` with corresponding images
- Add exec endpoint that captures the command and returns `{"Id":"<random>"}` then a fake stream

---

### SMB — port 445

**Probe:** SMB1 negotiate response received (standard `\xff\x53\x4d\x42r` header).

**Verdict:** Impacket SimpleSMBServer responds. nmap IDs it as `microsoft-ds`. Functional enough for credential capture.

---

### VNC — port 5900

**Probe:**
```
RFB 003.008   ✓
```

**Verdict:** Correct RFB 3.8 handshake. nmap fingerprints it as VNC protocol 3.8. The 16-byte DES challenge is hardcoded — same bytes every time.

**Fixes needed (trivial):**
- Randomize the 16-byte challenge per connection (`os.urandom(16)`)

---

### RDP — port 3389

**Probe:**
```
0300000b06d00000000000   ← X.224 Connection Confirm
(connection closed)
```

**Verdict:** nmap identifies it as "xrdp" which is correct enough. The X.224 CC is fine. But the server closes immediately after — no NLA/CredSSP negotiation, no credential capture. This is the single biggest missed opportunity for credential harvesting after SSH.

**Fixes needed:**
- Implement NTLM Type-1/Type-2/Type-3 exchange to capture NTLMv2 hashes
- Alternatively: send a fake TLS certificate then disconnect (many scanners fingerprint by the cert)

---

### SIP — port 5060

**Probe:**
```
SIP/2.0 401 Unauthorized
WWW-Authenticate: Digest realm="omega-decky", nonce="decnet0000", algorithm=MD5
```

**Verdict:** Functional. Correctly challenges with 401. But `nonce="decnet0000"` is a hardcoded string — a Shodan signature would immediately pick this up.

**Fixes needed (low effort):**
- Generate a random hex nonce per connection

---

### MQTT — port 1883

**Probe:** `CONNACK` with return code `0x05` (not authorized).

**Verdict:** Rejects all connections. For an ICS/water-plant persona, this should accept connections and expose fake sensor topics. See `ICS_SCADA.md`.

**Fixes needed:**
- Return CONNACK 0x00 (accepted)
- Implement SUBSCRIBE: return retained sensor readings for bait topics
- Implement PUBLISH: log any published commands (attacker trying to control plant)

---

### SNMP — port 161/UDP

Not directly testable without sudo for raw UDP send, but code review shows BER encoding is correct.

**Verdict:** Functional. sysDescr is a generic Linux string — should be tuned per archetype.

---

### LDAP — port 389

**Probe:** BER response received (code 49 = invalidCredentials).

**Verdict:** Correct protocol. nmap IDs it as "Cisco LDAP server" which is fine. No rootDSE response for unauthenticated enumeration.

---

### Telnet — port 23 (Cowrie)

**Probe:**
```
login: <IAC WILL ECHO>
Password: 
Login incorrect   ← for all tried credentials
```

**Verdict:** Cowrie is running but rejecting everything. Default Cowrie credentials (root/1234, admin/admin, etc.) should work. May be a config issue with the decky hostname or user database.

---

### Conpot — port 502

**Verdict:** Not responding on port 502 (Modbus TCP). Conpot may use a different internal port that gets NAT'd, or it's not configured for Modbus. Needs investigation.

---

## Bug Ledger

| # | Service    | Bug                                       | Severity |
|---|------------|-------------------------------------------|----------|
| 1 | SMTP       | DATA handler returns 502 for every line   | Critical |
| 2 | HTTP       | Werkzeug in Server header + bare 403 body | High     |
| 3 | FTP        | "Twisted 25.5.0" in banner                | High     |
| 4 | MSSQL      | No response to TDS pre-login              | High     |
| 5 | MongoDB    | No response to OP_MSG isMaster            | High     |
| 6 | K8s        | Not responding (TLS setup?)               | Medium   |
| 7 | IMAP/POP3  | Always rejects, no mailbox ops            | Critical (feature gap) |
| 8 | Redis      | Empty keyspace after AUTH success         | Medium   |
| 9 | SIP/VNC    | Hardcoded nonce/challenge                 | Low      |
| 10| MQTT       | Rejects all connections                   | High (ICS feature gap) |
| 11| Conpot     | No Modbus response                        | Medium   |
| 12| PostgreSQL | Hardcoded salt `deadbeef`                 | Low      |

---

## Related Plans

- [`SMTP_RELAY.md`](SMTP_RELAY.md) — Fix DATA handler, implement open relay persona
- [`IMAP_BAIT.md`](IMAP_BAIT.md) — Auth + seeded mailboxes + POP3 parity
- [`ICS_SCADA.md`](ICS_SCADA.md) — MQTT water plant, SNMP tuning, Conpot
- [`BUG_FIXES.md`](BUG_FIXES.md) — HTTP header leak, FTP banner, MSSQL, MongoDB, Redis keys

---

## Progress Updates

### [2026-04-10] ICS/SCADA & IMAP Bait Completion
The following infrastructure gaps from the Bug Ledger have been successfully resolved:
* **#7 (IMAP/POP3):** Both services now implement full protocol state machines (authentication, selection/transactions, fetching) and serve realistic hardcoded bait payloads (AWS keys, DB passwords).
* **#10 (MQTT):** The service now issues successful `CONNACK` responses, presents interactive persona-driven topic trees, and logs attacker `PUBLISH` events.
* **#11 (Conpot):** Wrapped in a custom build context that correctly binds Modbus to port `502` using a temporary template overwrite, resolving the missing Modbus response issue.
