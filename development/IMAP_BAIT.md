# IMAP Bait Mailboxes — Plan

> Scenario: attacker credential-stuffs IMAP, logs in as `admin`/`admin`,
> browses mail, finds juicy internal communications and credential leaks.

---

## Current state

Both IMAP and POP3 reject **all** credentials with a hard-coded failure.
No mailbox commands are implemented. An attacker that successfully guesses
credentials (which they can't, ever) would have nothing to read anyway.

This is the biggest missed opportunity in the whole stack.

---

## Design

### Credential policy

Accept a configurable set of username/password pairs. Defaults baked into
the image — typical attacker wordlist winners:

```
admin / admin
admin / password
admin / 123456
root  / root
mail  / mail
user  / user
```

Env var override: `IMAP_USERS=admin:admin,root:toor,user:letmein`

Wrong credentials → `NO [AUTHENTICATIONFAILED] Invalid credentials` (log the attempt).
Right credentials  → `OK` + full session.

### Fake mailboxes

One static mailbox tree, same for all users (honeypot doesn't need per-user isolation):

```
INBOX         (12 messages)
  Sent        (8 messages)
  Drafts      (1 message)
  Archive     (3 messages)
```

### Bait email content

Bait emails are seeded at startup from a `MAIL_SEED` list embedded in the server.
Content is designed to reward the attacker for staying in the session:

**INBOX messages (selected)**

| # | From | Subject | Bait payload |
|---|------|---------|-------------|
| 1 | devops@company.internal | AWS credentials rotation | `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| 2 | monitoring@company.internal | DB password changed | `mysql://admin:Sup3rS3cr3t!@10.0.1.5:3306/production` |
| 3 | noreply@github.com | Your personal access token | `ghp_16C7e42F292c6912E7710c838347Ae178B4a` |
| 4 | admin@company.internal | VPN config attached | `vpn.company.internal:1194 user=vpnadmin pass=VpnP@ss2024` |
| 5 | sysadmin@company.internal | Root password | New root pw: `r00tM3T00!` — change after first login |
| 6 | backup@company.internal | Backup job failed | Backup to `192.168.1.50:/mnt/nas` — credentials in /etc/backup.conf |
| 7 | alerts@company.internal | SSH brute-force alert | 47 attempts from 185.220.101.x against root — all blocked |

**Sent messages**

| # | To | Subject | Bait payload |
|---|-----|---------|-------------|
| 1 | vendor@external.com | API credentials | API key: `sk_live_xK3mF2...9aP` |
| 2 | helpdesk@company.internal | Need access reset | My password is `Winter2024!` — please reset MFA |

**Drafts**

| # | Subject | Bait payload |
|---|---------|-------------|
| 1 | DO NOT SEND - k8s secrets | `kubectl get secret admin-token -n kube-system -o yaml` output pasted in |

---

## Protocol implementation

### IMAP4rev1 commands to implement

```
CAPABILITY  → * CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN
LOGIN       → authenticate or reject
SELECT      → select INBOX / Sent / Drafts / Archive
LIST        → return folder tree
LSUB        → same as LIST (subscribed)
STATUS      → return EXISTS / RECENT / UNSEEN for a mailbox
FETCH       → return message headers or full body
UID FETCH   → same with UID addressing
SEARCH      → stub: return all UIDs (we don't need real search)
EXAMINE     → read-only SELECT
CLOSE       → deselect current mailbox
LOGOUT      → BYE + OK
NOOP        → OK
```

Commands NOT needed (return `BAD`): `STORE`, `COPY`, `APPEND`, `EXPUNGE`.
Attackers rarely run these. Logging `BAD` is fine if they do.

### Banner

Change from:
```
* OK [omega-decky] IMAP4rev1 Service Ready
```
To:
```
* OK Dovecot ready.
```

nmap currently says "(unrecognized)". Dovecot banner makes it ID correctly.

### CAPABILITY advertisement

```
* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN
```

### SELECT response

```
* 12 EXISTS
* 0 RECENT
* OK [UNSEEN 7] Message 7 is first unseen
* OK [UIDVALIDITY 1712345678] UIDs valid
* OK [UIDNEXT 13] Predicted next UID
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Deleted \Seen \*)] Limited
A3 OK [READ-WRITE] SELECT completed
```

### FETCH envelope/body

Message structs stored as Python dataclasses at startup. `FETCH 1:* (FLAGS ENVELOPE)` returns
envelope tuples in RFC 3501 format. `FETCH N BODY[]` returns the raw RFC 2822 message.

---

## POP3 parity

POP3 is much simpler. Same credential list. After successful PASS:

```
STAT  → +OK 12 48000   (12 messages, total ~48 KB)
LIST  → +OK 12 messages\r\n1 3912\r\n2 2048\r\n...\r\n.
RETR N → +OK <size>\r\n<raw message>\r\n.
TOP N L → +OK\r\n<first L body lines>\r\n.
UIDL  → +OK\r\n1 <uid>\r\n...\r\n.
DELE N → +OK Message deleted  (just log it, don't actually remove)
CAPA  → +OK\r\nTOP\r\nUSER\r\nUIDL\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nSASL\r\n.
```

---

## State machine (IMAP)

```
NOT_AUTHENTICATED
  → LOGIN success  → AUTHENTICATED
  → LOGIN fail     → NOT_AUTHENTICATED (log, stay open for retries)

AUTHENTICATED
  → SELECT / EXAMINE  → SELECTED
  → LIST / LSUB / STATUS / LOGOUT / NOOP  → stay AUTHENTICATED

SELECTED
  → FETCH / UID FETCH / SEARCH / EXAMINE / SELECT  → stay SELECTED
  → CLOSE / LOGOUT  → AUTHENTICATED or closed
```

---

## Files to change

| File | Change |
|------|--------|
| `templates/imap/server.py` | Full rewrite: state machine, credential check, mailbox commands, bait emails |
| `templates/pop3/server.py` | Extend: credential check, STAT/LIST/RETR/UIDL/TOP/DELE/CAPA |
| `tests/test_imap.py` | New: login flow, SELECT, FETCH, bad creds, all mailboxes |
| `tests/test_pop3.py` | New: login flow, STAT, LIST, RETR, CAPA |

---

## Implementation notes

- All bait emails are hardcoded Python strings — no files to load, no I/O.
- Use a module-level `MESSAGES: list[dict]` list with fields: `uid`, `flags`, `size`, `date`,
  `from_`, `to`, `subject`, `body` (full RFC 2822 string).
- `_format_envelope()` builds the IMAP ENVELOPE tuple string from the message dict.
- Thread safety: all state per-connection in the Protocol class. No shared mutable state.

---

## Env vars

| Var | Default | Description |
|-----|---------|-------------|
| `IMAP_USERS` | `admin:admin,root:root,mail:mail` | Accepted credentials (user:pass,...) |
| `IMAP_BANNER` | `* OK Dovecot ready.` | Greeting line |
| `NODE_NAME` | `mailserver` | Hostname in responses |

---

## Verification against live decky

```bash
# Credential test (should accept)
printf "A1 LOGIN admin admin\r\nA2 SELECT INBOX\r\nA3 FETCH 1:3 (FLAGS ENVELOPE)\r\nA4 FETCH 5 BODY[]\r\nA5 LOGOUT\r\n" | nc 192.168.1.200 143

# Credential test (should reject)
printf "A1 LOGIN admin wrongpass\r\n" | nc 192.168.1.200 143

# nmap fingerprint check (expect "Dovecot imapd")
nmap -p 143 -sV 192.168.1.200
```
