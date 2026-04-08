# Initial steps

# Architecture

## DECNET-UNIHOST model

The unihost model is a mode in which DECNET deploys an _n_ amount of machines from a single one. This execution model lives in a decoy network which is accessible to an attacker from the outside.

Each decky (the son of the DECNET unihost) should have different services (RDP, SMB, SSH, FTP, etc) and all of them should communicate with an external, isolated network, which aggregates data and allows
visualizations to be made. Think of the ELK stack. That data is then passed back via Logstash or other methods to a SIEM device or something else that may be beneficiated by this collected data.

## DECNET-MULTIHOST (SWARM) model

The SWARM model is similar to the UNIHOST model, but the difference is that instead of one real machine, we have n>1 machines. Same thought process really, but deployment may be different.
A low cost option and fairly automatable one is the usage of Ansible, sshpass, or other tools.

# Modus operandi

## Docker-Compose

I will use Docker Compose extensively for this project. The reasons are:
- Easily managed.
- Easily extensible.
- Less overhead.

To be completely transparent: I asked Deepseek to write the initial `docker-compose.yml` file. It was mostly boilerplate, and most of it mainly modified or deleted. It doesn't exist anymore.

## Distro to use.

I will be using the `debian:bookworm-slim` image for all the containers. I might think about mixing in there some Ubuntu or a Centos, but for now, Debian will do just fine.

The distro I'm running is WSL Kali Linux. Let's hope this doesn't cause any problems down the road.

## Networking

It was a hussle, but I think MACVLAN or IPVLAN (thanks @Deepseek!) might work. The reasoning behind picking this networking driver is that for the project to work, it requires having containers the entire container accessible from the network. This is to attempt to masquarede them as real, live machines.

Now, we will need a publicly accesible, real server that has access to this "internal" network. I'll try MACVLAN first.

### MACVLAN Tests

I will first use the default network to see what happens.

```
docker network create -d macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  -o parent=eth0 localnet
```

#### Issues

This initial test doesn't seem to be working. Might be that I'm using WSL, so I downloaded a Ubuntu 22.04 Server ISO. I'll try the MACVLAN network on it. Now, if that doesn't work, I don't see how the 802.1q would work, at least on _my network_. Perhaps if I had a switch I could make it work, but currently I don't have one :c

---

# TODO

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
- [ ] **Config validation CLI** — `decnet validate my.ini` to dry-check an INI config before deploying.
- [ ] **Config generator wizard** — `decnet wizard` interactive prompt to generate an INI config without writing one by hand.
