# DECNET Development Roadmap

## 🛠️ Service Realism & Interaction (First Release Path)
*Goal: Ensure every service is interactive enough to feel real during manual exploration.*

### Remote Access & Shells
- [ ] **SSH (Cowrie)** — Custom filesystem, realistic user database, and command execution.
- [ ] **Telnet (Cowrie)** — Realistic banner and command emulation.
- [ ] **RDP** — Realistic NLA authentication and screen capture (where possible).
- [ ] **VNC** — Realistic RFB protocol handshake and authentication.
- [x] **Real SSH** — High-interaction sshd with shell logging.

### Databases
- [ ] **MySQL** — Support for common SQL queries and realistic schema.
- [ ] **Postgres** — Realistic version strings and basic query support.
- [ ] **MSSQL** — Realistic TDS protocol handshake.
- [ ] **MongoDB** — Support for common Mongo wire protocol commands.
- [x] **Redis** — Support for basic GET/SET/INFO commands.
- [ ] **Elasticsearch** — Realistic REST API responses for `/_cluster/health` etc.

### Web & APIs
- [x] **HTTP** — Flexible templates (WordPress, phpMyAdmin, etc.) with logging.
- [ ] **Docker API** — Realistic responses for `docker version` and `docker ps`.
- [ ] **Kubernetes (K8s)** — Mocked kubectl responses and basic API exploration.
- [x] **LLMNR** — Realistic local name resolution responses via responder-style emulation.

### File Transfer & Storage
- [ ] **SMB** — Realistic share discovery and basic file browsing.
- [x] **FTP** — Support for common FTP commands and directory listing.
- [ ] **TFTP** — Basic block-based file transfer emulation.

### Directory & Mail
- [ ] **LDAP** — Basic directory search and authentication responses.
- [x] **SMTP** — Mail server banners and basic EHLO/MAIL FROM support.
- [x] **IMAP** — Realistic mail folder structure and auth.
- [x] **POP3** — Basic mail retrieval protocol emulation.

### Industrial & IoT (ICS)
- [x] **MQTT** — Basic topic subscription and publishing support.
- [x] **SNMP** — Realistic MIB responses for common OIDs.
- [ ] **SIP** — Basic VoIP protocol handshake and registration.
- [x] **Conpot** — SCADA/ICS protocol emulation (Modbus, etc.).

---

## Core / Hardening

- [x] **Attacker fingerprinting** — HTTP User-Agent and VNC client version stored as `fingerprint` bounties. TLS JA3/JA4 and TCP window sizes require pcap (out of scope). SSH client banner deferred pending asyncssh server.
- [ ] **Canary tokens** — Embed fake AWS keys and honeydocs into decky filesystems.
- [ ] **Tarpit mode** — Slow down attackers by drip-feeding bytes or delaying responses.
- [x] **Dynamic decky mutation** — Rotate exposed services or OS fingerprints over time.
- [x] **Credential harvesting DB** — Centralized database for all username/password attempts.
- [ ] **Session recording** — Full capture for SSH/Telnet sessions.
- [ ] **Payload capture** — Store and hash files uploaded by attackers.

## Detection & Intelligence

- [ ] **Real-time alerting** — Webhook/Slack/Telegram notifications for first-hits.
- [ ] **Threat intel enrichment** — Auto-lookup IPs against AbuseIPDB, Shodan, and GreyNoise.
- [ ] **Attack campaign clustering** — Group sessions by signatures and timing patterns.
- [ ] **GeoIP mapping** — Visualize attacker origin and ASN data on a map.
- [ ] **TTPs tagging** — Map observed behaviors to MITRE ATT&CK techniques.

## Dashboard & Visibility

- [x] **Web dashboard** — Real-time React SPA + FastAPI backend for logs and fleet status.
- [x] **Decky Inventory** — Dedicated "Decoy Fleet" page showing all deployed assets.
- [ ] **Pre-built Kibana/Grafana dashboards** — Ship JSON exports for ELK/Grafana.
- [~] **CLI live feed** — `decnet watch` — WON'T IMPLEMENT: redundant with `tail -f` on the existing log file; adds bloat without meaningful value.
- [x] **Traversal graph export** — Export attacker movement as JSON (via CLI).

## Deployment & Infrastructure

- [ ] **SWARM / multihost mode** — Ansible-based orchestration for multi-node deployments.
- [ ] **Terraform/Pulumi provider** — Cloud-hosted decky deployment.
- [ ] **Kubernetes deployment mode** — Run deckies as K8s pods.
- [x] **Lifecycle Management** — Automatic API process termination on `teardown`.
- [x] **Health monitoring** — Active vs. Deployed decky tracking in the dashboard.

## Services & Realism

- [ ] **HTTPS/TLS support** — Honeypots with SSL certificates.
- [ ] **Fake Active Directory** — Convincing AD/LDAP emulation.
- [ ] **Realistic web apps** — Fake WordPress, Grafana, and phpMyAdmin templates.
- [ ] **OT/ICS profiles** — Expanded Modbus, DNP3, and BACnet support.

## Developer Experience

- [x] **API Fuzzing** — Property-based testing for all web endpoints.
- [x] **CI/CD pipeline** — Automated testing and linting via Gitea Actions.
- [x] **Strict Typing** — Project-wide enforcement of PEP 484 type hints.
- [ ] **Plugin SDK docs** — Documentation for adding custom services.
- [ ] **Config generator wizard** — `decnet wizard` for interactive setup.
