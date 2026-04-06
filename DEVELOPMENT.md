# TODO

This is a list of DEVELOPMENT TODOs. Features, development experience, usage, documentation, etcetera.

## Core / Hardening

- [ ] **Attacker fingerprinting** — Beyond IP logging: capture TLS JA3/JA4 hashes, TCP window sizes, User-Agent strings, SSH client banners, and tool signatures (nmap, masscan, Metasploit, Cobalt Strike). Build attacker profiles across sessions.
- [ ] **Canary tokens** — Embed canary URLs, fake AWS keys, fake API tokens, and honeydocs (PDF/DOCX with phone-home URLs) into decky filesystems. Fire an alert the moment one is used.
- [ ] **Tarpit mode** — Slow down attackers by making services respond extremely slowly (e.g., SSH that takes 60s to reject, HTTP that drip-feeds bytes). Wastes attacker time and resources.
- [ ] **Dynamic decky mutation** — Deckies that change their exposed services or OS fingerprint over time to confuse port-scan caching and appear more "alive."
- [ ] **Credential harvesting DB** — Every username/password attempt across all services lands in a queryable database. Expose via CLI (`decnet creds`) and flag reuse across deckies.
- [ ] **Session recording** — Full session capture for SSH/Telnet (keystroke logs, commands run, files downloaded). Cowrie already does this — surface it better in the CLI and correlation engine.
- [ ] **Payload capture** — Store every file uploaded or command executed by an attacker. Hash and auto-submit to VirusTotal or a local sandbox.

## Detection & Intelligence

- [ ] **Real-time alerting** — Webhook/Slack/Telegram notifications when an attacker hits a decky for the first time, crosses N deckies (lateral movement), or uses a known bad IP.
- [ ] **Threat intel enrichment** — Auto-lookup attacker IPs against AbuseIPDB, Shodan, GreyNoise, and AlienVault OTX. Tag known scanners vs. targeted attackers.
- [ ] **Attack campaign clustering** — Group attacker sessions by tooling signatures, timing patterns, and credential sets. Identify coordinated campaigns hitting multiple deckies.
- [ ] **GeoIP mapping** — Attacker origin on a world map. Correlate with ASN data to identify cloud exit nodes, VPNs, and Tor exits.
- [ ] **TTPs tagging** — Map observed attacker behaviors to MITRE ATT&CK techniques automatically. Tag events in the correlation engine.
- [ ] **Honeypot interaction scoring** — Score attackers on a scale: casual scanner vs. persistent targeted attacker, based on depth of interaction and commands run.

## Dashboard & Visibility

- [ ] **Web dashboard** — Real-time web UI showing live decky status, attacker activity, traversal graphs, and credential stats. Could be a simple FastAPI + HTMX or a full React app.
- [ ] **Pre-built Kibana/Grafana dashboards** — Ship dashboard JSON exports out of the box so ELK/Grafana deployments are plug-and-play.
- [ ] **CLI live feed** — `decnet watch` command: tail all decky logs in a unified, colored terminal stream (like `docker-compose logs -f` but prettier).
- [ ] **Traversal graph export** — Export attacker traversal graphs as DOT/Graphviz or JSON for visualization in external tools.
- [ ] **Daily digest** — Automated daily summary email/report: new attackers, top credentials tried, most-hit services.

## Deployment & Infrastructure

- [ ] **SWARM / multihost mode** — Full Ansible-based orchestration for deploying deckies across N real hosts.
- [ ] **Terraform/Pulumi provider** — Spin up cloud-hosted deckies on AWS/GCP/Azure with one command. Useful for internet-facing honeynets.
- [ ] **Auto-scaling** — When attack traffic increases, automatically spawn more deckies to absorb and log more activity.
- [ ] **Kubernetes deployment mode** — Run deckies as Kubernetes pods for environments already running k8s.
- [ ] **Proxmox/libvirt backend** — Full VM-based deckies instead of containers, for even more realistic OS fingerprints and behavior. Docker for speed; VMs for realism.
- [ ] **Raspberry Pi / ARM support** — Low-cost physical honeynets using RPis. Validate ARM image builds.
- [ ] **Decky health monitoring** — Watchdog that auto-restarts crashed deckies and alerts if a service goes dark.

## Services & Realism

- [ ] **HTTPS/TLS support** — HTTP honeypot with a self-signed or Let's Encrypt cert. Many real-world services use HTTPS; plain HTTP stands out.
- [ ] **Fake Active Directory** — A convincing fake AD/LDAP with fake users, groups, and GPOs. Attacker tools like BloodHound should get juicy (fake) data.
- [ ] **Fake file shares** — SMB/NFS shares pre-populated with enticing but fake files: "passwords.xlsx", "vpn_config.ovpn", "backup_keys.tar.gz". All instrumented to detect access.
- [ ] **Realistic web apps** — HTTP honeypot serving convincing fake apps: a fake WordPress, a fake phpMyAdmin, a fake Grafana login — all logging every interaction.
- [ ] **OT/ICS profiles** — Expand Conpot support: Modbus, DNP3, BACnet, EtherNet/IP. Convincing industrial control system decoys.
- [ ] **Printer/IoT archetypes** — Expand existing printer/camera archetypes with actual service emulation (IPP, ONVIF, WS-Discovery).
- [ ] **Service interaction depth** — Some services currently just log the connection. Deepen interaction: fake MySQL that accepts queries and returns realistic fake data, fake Redis that stores and retrieves dummy keys.

## Developer Experience

- [ ] **Plugin SDK docs** — Full documentation and an example plugin for adding custom services. Lower the barrier for community contributions.
- [ ] **Integration tests** — Full deploy/teardown cycle tests against a real Docker daemon (not just unit tests).
- [ ] **Per-service tests** — Each of the 29 service implementations deserves its own test coverage.
- [x] **CI/CD pipeline** — GitHub/Gitea Actions: run tests on push, lint, build Docker images, publish releases.
    - ci.yaml contains several steps for the CI/CD pipeline. Mainly:
        - Trivy checks for Docker containers.
        - Ruff linting.
        - Pytests.
        - Bandit SAST.
        - pip-audit.
- [ ] **Config validation CLI** — `decnet validate my.ini` to dry-check an INI config before deploying.
- [ ] **Config generator wizard** — `decnet wizard` interactive prompt to generate an INI config without writing one by hand.
- [ ] **Gitea Wiki** — Set up the repository wiki with structured docs across the following pages:
    - **Home** — Project overview, goals, and navigation index.
    - **Architecture** — UNIHOST vs SWARM models, the two-network design (decoy-facing vs isolated logging), MACVLAN/IPVLAN, log pipeline (Cowrie → Logstash → ELK → SIEM), WSL limitations.
    - **General Usage** — What DECNET can do and how: deploying deckies, choosing services, using `--randomize-services`, reading status, tearing down. Archetypes explained (what they are, how they group services into realistic machine personas — e.g. a Windows workstation archetype exposes RDP+SMB+LDAP, a Linux server exposes SSH+FTP+MySQL). List of built-in archetypes. How to pick an archetype vs. manually specifying services.
    - **Custom Services** — How the plugin registry works, anatomy of a service plugin, step-by-step guide to writing and registering a custom service, how to package it for reuse.
    - **Configuration Reference** — Full INI config option breakdown, all CLI flags (`--mode`, `--deckies`, `--interface`, `--log-target`, `--randomize-services`, etc.), environment variables.
    - **Deployment Guides** — UNIHOST quickstart (bare metal/VM), SWARM/multihost with Ansible (once implemented), cloud deployment via Terraform (once implemented), Raspberry Pi / ARM builds.
    - **Service Reference** — Full table of all 29 services: port, protocol, base image, interaction depth, and any known fingerprint quirks.
    - **Attacker Intelligence** — Credential harvesting (`decnet creds`), session recording playback, threat intel enrichment (AbuseIPDB, GreyNoise, Shodan, OTX), MITRE ATT&CK tagging, campaign clustering.
    - **Operations** — Health monitoring, watchdog behavior, teardown procedures, log rotation, troubleshooting common issues.
