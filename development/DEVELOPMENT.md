# DECNET Development Roadmap

## Core / Hardening

- [ ] **Attacker fingerprinting** — Capture TLS JA3/JA4 hashes, TCP window sizes, User-Agent strings, and SSH client banners.
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
- [x] **CLI live feed** — `decnet watch` command for a unified, colored terminal stream.
- [ ] **Traversal graph export** — Export attacker movement as DOT or JSON.

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
