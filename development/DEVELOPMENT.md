# DECNET Development Roadmap

## 🛠️ Service Realism & Interaction (First Release Path)
*Goal: Ensure every service is interactive enough to feel real during manual exploration.*

### Remote Access & Shells
- [~] **SSH (Cowrie)** — Custom filesystem, realistic user database, and command execution: DELETED! Will use real OpenSSH for the highest interaction possible.
- [~] **Telnet (Cowrie)** — Realistic banner and command emulation: DELETED! Will use Busybox Telnetd for the same reasons as above.
- [x] **RDP** — Realistic NLA authentication and screen capture (where possible).
- [x] **VNC** — Realistic RFB protocol handshake and authentication.
- [x] **Real SSH** — High-interaction sshd with shell logging.

### Databases
- [x] **MySQL** — Support for common SQL queries and realistic schema.
- [x] **Postgres** — Realistic version strings and basic query support.
- [x] **MSSQL** — Realistic TDS protocol handshake.
- [x] **MongoDB** — Support for common Mongo wire protocol commands.
- [x] **Redis** — Support for basic GET/SET/INFO commands.
- [x] **Elasticsearch** — Realistic REST API responses for `/_cluster/health` etc.

### Web & APIs
- [x] **HTTP** — Flexible templates (WordPress, phpMyAdmin, etc.) with logging.
- [x] **Docker API** — Realistic responses for `docker version` and `docker ps`.
- [x] **Kubernetes (K8s)** — Mocked kubectl responses and basic API exploration.
- [x] **LLMNR** — Realistic local name resolution responses via responder-style emulation.

### File Transfer & Storage
- [x] **SMB** — Realistic share discovery and basic file browsing.
- [x] **FTP** — Support for common FTP commands and directory listing.
- [x] **TFTP** — Basic block-based file transfer emulation.

### Directory & Mail
- [x] **LDAP** — Basic directory search and authentication responses.
- [x] **SMTP** — Mail server banners and basic EHLO/MAIL FROM support.
- [x] **IMAP** — Realistic mail folder structure and auth.
- [x] **POP3** — Basic mail retrieval protocol emulation.

### Industrial & IoT (ICS)
- [x] **MQTT** — Basic topic subscription and publishing support.
- [x] **SNMP** — Realistic MIB responses for common OIDs.
- [x] **SIP** — Basic VoIP protocol handshake and registration.
- [x] **Conpot** — SCADA/ICS protocol emulation (Modbus, etc.).

---

## Core / Hardening

- [~] **Attacker fingerprinting** — HTTP User-Agent, VNC client version stored as `fingerprint` bounties. JA3/JA3S in progress (sniffer container). HASSH, JA4+, TCP stack, JARM planned (see Attacker Intelligence section).
- [x] **Canary tokens** — Embed fake AWS keys and honeydocs into decky filesystems.
- [ ] **Tarpit mode** — Slow down attackers by drip-feeding bytes or delaying responses.
- [x] **Dynamic decky mutation** — Rotate exposed services or OS fingerprints over time.
- [x] **Credential harvesting DB** — Centralized database for all username/password attempts.
- [x] **Session recording** — Full capture for SSH/Telnet sessions. -> sessrec pty relay writes asciinema v2 day-shards per decky; paged API + SessionDrawer replay in the dashboard.
- [x] **Payload capture** — Store and hash files uploaded by attackers. -> Via inotifywait and custom C wrappers.

## Detection & Intelligence

- [x] **Real-time alerting via webhooks** — Admin-configurable outbound webhooks (SIEM/SOAR integration: Wazuh/Shuffle/TheHive/n8n) with HMAC-SHA256 signing, topic-pattern filtering, and bounded retry. Slack/Telegram-specific senders remain as per-destination work (they accept generic webhook payloads already).
- [x] **Threat intel enrichment** — Auto-lookup IPs against AbuseIPDB, Shodan, and GreyNoise. -> Out-of-band `decnet enrich` worker, woken on `attacker.scored`/`attacker.observed`. v1 ships GreyNoise Community + AbuseIPDB + abuse.ch (Feodo Tracker bulk feed and ThreatFox per-IP). Shodan / Censys / OTX backlogged in DEVELOPMENT_V2.md.
- [x] **Attack campaign clustering** — Group sessions by signatures and timing patterns.
- [x] **GeoIP mapping** — Visualize attacker origin and ASN data on a map.
- [ ] **TTPs tagging** — Map observed behaviors to MITRE ATT&CK techniques.

## Dashboard & Visibility

- [x] **Web dashboard** — Real-time React SPA + FastAPI backend for logs and fleet status.
- [x] **Decky Inventory** — Dedicated "Decoy Fleet" page showing all deployed assets.
- [~] **Pre-built Kibana/Grafana dashboards** — Ship JSON exports for ELK/Grafana. -> Deferred to post-v1 release.
- [~] **CLI live feed** — `decnet watch` — WON'T IMPLEMENT: redundant with `tail -f` on the existing log file; adds bloat without meaningful value.
- [x] **Traversal graph export** — Export attacker movement as JSON (via CLI).

## Deployment & Infrastructure

- [x] **SWARM / multihost mode** — Ansible-based orchestration for multi-node deployments. -> Not Ansible based, but bundle based via the UI.
- [~] **Terraform/Pulumi provider** — Cloud-hosted decky deployment. -> Deferred to post-v1 release.
- [~] **Kubernetes deployment mode** — Run deckies as K8s pods. -> Deferred to post-v1 release.
- [x] **Lifecycle Management** — Automatic API process termination on `teardown`.
- [x] **Health monitoring** — Active vs. Deployed decky tracking in the dashboard.

## Services & Realism

- [x] **HTTPS/TLS support** — Honeypots with SSL certificates.
- [~] **Fake Active Directory** — Convincing AD/LDAP emulation. -> Deferred to post-v1 release.
- [~] **Realistic web apps** — Fake WordPress, Grafana, and phpMyAdmin templates. -> Deferred to post-v1 release.
- [~] **OT/ICS profiles** — Expanded Modbus, DNP3, and BACnet support. -> Deferred to post-v1 release. Some profiles exist, but they are not comprehensive.

## Attacker Intelligence Collection
*Goal: Build the richest possible attacker profile from passive observation across all 26 services.*

- `decnet/vectorstore/` substrate is scaffolded and `sqlite-vec` is wired (factory + base + impl). No producers/consumers yet — reserved for the future statistical re-identification engine.

### TLS/SSL Fingerprinting (via sniffer container)
- [x] **JA3/JA3S** — TLS ClientHello/ServerHello fingerprint hashes
- [x] **JA4+ family** — JA4, JA4S, JA4H, JA4L (latency/geo estimation via RTT)
- [x] **JARM** — Active server fingerprint; identifies C2 framework from TLS server behavior
- [~] **CYU** — Citrix-specific TLS fingerprint: WILL NOT implement pre-v1. Don't have that kind of data.
- [x] **TLS session resumption behavior** — Identifies tooling by how it handles session tickets
- [x] **Certificate details** — CN, SANs, issuer, validity period, self-signed flag (attacker-run servers)

### Timing & Behavioral
- [x] **Inter-packet arrival times** — OS TCP stack fingerprint + beaconing interval detection
- [x] **TTL values** — Rough OS / hop-distance inference
- [x] **TCP window size & scaling** — p0f-style OS fingerprinting
- [x] **Retransmission patterns** — Identify lossy paths / throttled connections
- [x] **Beacon jitter variance** — Attribute tooling: Cobalt Strike vs. Sliver vs. Havoc have distinct profiles
- [x] **C2 check-in cadence** — Detect beaconing vs. interactive sessions
- [x] **Data exfil timing** — Behavioral sequencing relative to recon phase

### Protocol Fingerprinting
- [x] **TCP/IP stack** — ISN patterns, DF bit, ToS/DSCP, IP ID sequence (random/incremental/zero)
- [x] **HASSH / HASSHServer** — SSH KEX algo, cipher, MAC order → tool fingerprint
- [x] **HTTP/2 fingerprint** — GREASE values, settings frame order, header pseudo-field ordering
- [ ] **QUIC fingerprint** — Connection ID length, transport parameters order
- [ ] **DNS behavior** — Query patterns, recursion flags, EDNS0 options, resolver fingerprint
- [x] **HTTP header ordering** — Tool-specific capitalization and ordering quirks

### Network Topology Leakage
- [x] **X-Forwarded-For mismatches** — Detect VPN/proxy slip vs. actual source IP
- [ ] **ICMP error messages** — Internal IP leakage from misconfigured attacker infra
- [ ] **IPv6 link-local leakage** — IPv6 addrs leaked even over IPv4 VPN (common opsec fail)
- [ ] **mDNS/LLMNR leakage** — Attacker hostname/device info from misconfigured systems

### Geolocation & Infrastructure
- [x] **ASN lookup** — Source IP autonomous system number and org name
- [ ] **BGP prefix / RPKI validity** — Route origin legitimacy
- [x] **PTR records** — rDNS for attacker IPs (catches infra with forgotten reverse DNS)
- [ ] **Latency triangulation** — JA4L RTT estimates for rough geolocation

### Service-Level Behavioral Profiling
- [x] **Commands executed** — Full command log per session (SSH, Telnet, FTP, Redis, DB services)
- [x] **Services actively interacted with** — Distinguish port scans from live exploitation attempts
- [x] **Tooling attribution** — Byte-sequence signatures from known C2 frameworks in handshakes
- [x] **Credential reuse patterns** — Same username/password tried across multiple deckies/services
- [x] **Payload signatures** — Hash and classify uploaded files, shellcode, exploit payloads

---

## Developer Experience

- [x] **API Fuzzing** — Property-based testing for all web endpoints.
- [x] **CI/CD pipeline** — Automated testing and linting via Gitea Actions.
- [x] **Strict Typing** — Project-wide enforcement of PEP 484 type hints.
- [x] **Plugin SDK docs** — Documentation for adding custom services.
- [ ] **Config generator wizard** — `decnet wizard` for interactive setup.

## API Improvements

- [x] Enable up to 250 concurrent users with close to zero performance degradation.
- [x] Enable up to 100 requests per second with close to zero performance degradation.

## MazeNET

- [x] Initial MazeNET implementation via DAG recursive graphs.
- [x] Usable UI.
- [x] Random, seed-based network topologies.
- [x] Manual topology creation via war map.
- [x] UI based topology teardowns.
- [x] SWARM-based topology deployment.
- [x] UI based SWARM topology deployments.
