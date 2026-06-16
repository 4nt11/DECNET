<div align="center">

<img src="assets/decnet-logo.svg" alt="DECNET — Deception Network" width="560">

**A honeypot deception network framework.**

Spin up a fleet of fake machines — **deckies** — that look like real, heterogeneous LAN hosts to anyone scanning the network. Each decky gets its own MAC, IP, hostname, services, OS fingerprint, and log pipeline. Attackers probe; DECNET traps every interaction; a full intelligence stack profiles, clusters, and attributes their behaviour.

<br>

[![PyPI version](https://img.shields.io/pypi/v/decnet.svg)](https://pypi.org/project/decnet/)
[![Python](https://img.shields.io/pypi/pyversions/decnet.svg)](https://pypi.org/project/decnet/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg?logo=ruff&logoColor=white)](https://github.com/astral-sh/ruff)
[![Platform](https://img.shields.io/badge/platform-Linux-333.svg?logo=linux&logoColor=white)](#requirements)

[Quick Start](#quick-start) · [Architecture](#architecture) · [REST API](#rest-api--web-dashboard) · [MazeNET](#mazenet-topology) · [Support](https://ko-fi.com/C0C31YDLB5)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/C0C31YDLB5)

</div>

---

## Table of Contents

- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [CLI Reference](#cli-reference)
- [REST API & Web Dashboard](#rest-api--web-dashboard)
- [Swarm Mode](#swarm-mode)
- [Agent Mode](#agent-mode)
- [Service Bus](#service-bus)
- [Attacker Intelligence](#attacker-intelligence)
- [MazeNET Topology](#mazenet-topology)
- [Canary Tokens](#canary-tokens)
- [TTP Tagging & Export](#ttp-tagging--export)
- [Archetypes](#archetypes)
- [Services](#services)
- [OS Fingerprint Spoofing](#os-fingerprint-spoofing)
- [Distro Profiles](#distro-profiles)
- [Config File](#config-file)
- [Environment Configuration](#environment-configuration)
- [Logging](#logging)
- [Network Drivers](#network-drivers)
- [Writing a Custom Service Plugin](#writing-a-custom-service-plugin)
- [Development & Testing](#development--testing)

---

## How It Works

```
Attacker scans 192.168.1.110–119
         │
         ▼
  ┌──────────────────────────────────────────────┐
  │            DECNET LAN (MACVLAN)              │
  │                                              │
  │  decky-01  192.168.1.110  ssh + http         │
  │  decky-02  192.168.1.111  rdp + smb + mssql  │
  │  decky-03  192.168.1.112  mqtt + snmp         │
  │  ...                                         │
  └──────────────────────────────────────────────┘
         │
         ▼ RFC 5424 syslog-over-TLS (cross-host) / UNIX socket (local)
  ┌──────────────────────────────────────────────┐
  │           DECNET Master Node                 │
  │  FastAPI REST API  ·  Web Dashboard          │
  │  Profiler  ·  Clusterer  ·  Correlator       │
  │  MazeNET  ·  Canary  ·  TTP Engine           │
  └──────────────────────────────────────────────┘
```

Each decky is a small cluster of Docker containers sharing one network namespace:

- **Base container** — holds the MACVLAN IP, sets TCP/IP stack sysctls for OS fingerprint spoofing, runs `sleep infinity`.
- **Service containers** — one per honeypot service, all sharing the base's network so they appear to come from the same IP.

From the outside a decky looks identical to a real machine: its own MAC address, IP, hostname, and a TCP/IP stack tuned to the OS it impersonates. Internally, every attacker interaction flows through a log collector, the service bus, and into the intelligence pipeline.

---

## Requirements

- Linux host (bare metal or VM — WSL has MACVLAN limitations)
- Docker Engine 24+
- Python 3.11–3.13 (Python 3.14 is not yet supported — see [stress test notes](#stress-testing))
- Node.js 18+ (required for canary token JS obfuscation)
- Root / `sudo` for network setup (MACVLAN creation, host interface config)
- NIC in promiscuous mode for MACVLAN (or use `--ipvlan` on WiFi)

---

## Installation

```bash
git clone https://git.resacachile.cl/anti/DECNET
cd DECNET
pip install -e .
```

With optional tracing (OpenTelemetry):

```bash
pip install -e ".[tracing]"
```

Verify:

```bash
decnet --help
decnet services      # list all 25 registered honeypot services
decnet archetypes    # list machine archetype profiles
decnet distros       # list available OS distro profiles
```

---

## Quick Start

### Dry run — generate compose, no containers

```bash
decnet deploy --mode unihost --deckies 5 --randomize-services --dry-run
```

### Deploy with random services

```bash
sudo decnet deploy --mode unihost --deckies 5 --interface eth0 --randomize-services
```

### Start the API server and web dashboard

Recommended (systemd-managed):

```bash
sudo .venv/bin/decnet init                          # first-time setup: writes systemd units
sudo systemctl start "decnet-*.service"             # start all DECNET services
```

For development / quick runs, start the processes directly in the foreground:

```bash
decnet api start        # REST API on :8000
decnet web start        # Dashboard on :8080
```

### Check status

```bash
decnet status
```

### Tear everything down

```bash
sudo decnet teardown --all
sudo decnet teardown --id decky-02   # single decky
```

---

## Architecture

```
decnet/
├── cli/                  # Typer CLI commands (one module per group)
├── web/
│   ├── api.py            # FastAPI app factory, lifespan, workers
│   ├── auth.py           # JWT + bcrypt authentication
│   ├── router/           # Route modules (attackers, deckies, logs, topology, …)
│   ├── db/
│   │   ├── models/       # SQLModel tables (one file per domain)
│   │   ├── sqlite/       # SQLite backend
│   │   └── mysql/        # MySQL/asyncmy backend
│   ├── ingester.py       # Log ingestion worker (bus → DB)
│   └── worker_registry.py
├── bus/                  # DECNET ServiceBus (UNIX socket pub/sub)
│   ├── topics.py         # Canonical topic hierarchy
│   ├── unix_server.py    # Broker process
│   └── unix_client.py
├── collector/            # Local Docker log collector → bus
├── profiler/             # Attacker behavioural profiling
│   ├── behavioral.py     # Session fingerprinting
│   ├── fingerprint.py    # JA3 / tool signatures
│   ├── classify.py       # Attacker classification
│   ├── timing.py         # Inter-probe timing analysis
│   ├── phases.py         # Kill-chain phase detection
│   └── behave_shell/     # BEHAVE framework adapter
├── clustering/           # UKC attacker clustering
│   └── impl/
├── correlation/          # Identity / campaign formation
│   ├── engine.py         # Correlation rule engine
│   ├── attribution/      # Attribution state machine
│   └── graph.py          # Attacker relationship graph
├── canary/               # Canary token system
│   ├── planter.py        # Token placement
│   ├── cultivator.py     # Trigger detection
│   ├── dns_server.py     # DNS canary listener
│   └── generators/       # Token type generators
├── ttp/                  # TTP tagging & threat intelligence
│   ├── attack_stix.py    # MITRE ATT&CK STIX 2.1 parser
│   ├── stix_export.py    # STIX bundle export
│   ├── misp_export.py    # MISP event export
│   └── store/            # Inotify-backed rule store
├── agent/                # Remote DECNET agent (swarm node)
│   ├── server.py         # Agent FastAPI app
│   ├── heartbeat.py      # Master heartbeat
│   └── topology_ops.py   # Agent-side topology operations
├── engine/               # Decky container lifecycle engine
│   ├── deployer.py       # Docker bring-up / teardown
│   └── reaper.py         # Stranded container cleanup
├── fleet/                # Fleet reconciler (desired vs actual state)
├── lifecycle/            # Decky lifecycle state machine
├── orchestrator/         # Synthetic traffic / file / email injection
├── mutator/              # Behavioural mutation engine
├── tarpit/               # Connection tarpitting
├── sniffer/              # Passive packet capture
├── geoip/                # GeoIP + RIR lookup
├── asn/                  # ASN lookup (ip-to-asn)
├── intel/                # Threat intelligence feed integration
├── artifacts/            # Captured file artifact storage
├── net/                  # Subnet allocation helpers
├── archetypes.py         # Machine archetype profiles
├── distros.py            # OS distro profiles, hostname generation
├── os_fingerprint.py     # TCP/IP sysctl profiles per OS family
├── composer.py           # Generates docker-compose.yml
├── config.py             # Pydantic config models + state persistence
├── config_ini.py / ini_loader.py
├── telemetry.py          # OpenTelemetry tracing (optional)
└── env.py                # Environment variable declarations
```

### Container model

```
decky-01  (base)        ← MACVLAN IP owner; sleep infinity; sysctls applied here
  ├─ decky-01-ssh       ← network_mode: service:decky-01  (shares IP + MAC)
  ├─ decky-01-http      ← network_mode: service:decky-01
  └─ decky-01-smb       ← network_mode: service:decky-01
```

---

## CLI Reference

The full command tree has grown significantly. Commands are gated by deployment mode — master-only commands are hidden when `DECNET_MODE=agent`.

### Decky deployment

| Command | Description |
|---|---|
| `decnet deploy` | Deploy deckies (unihost or swarm mode) |
| `decnet teardown` | Stop and remove deckies |
| `decnet status` | Print fleet state table |

#### `decnet deploy` flags

| Flag | Default | Description |
|---|---|---|
| `--mode` | `unihost` | `unihost` or `swarm` |
| `--deckies` / `-n` | — | Number of deckies |
| `--interface` / `-i` | auto | Host NIC for MACVLAN |
| `--subnet` | auto | LAN CIDR |
| `--ip-start` | auto | First decky IP |
| `--services` | — | Comma-separated service slugs |
| `--randomize-services` | false | Random services per decky |
| `--distro` | auto-cycled | Distro slugs |
| `--randomize-distros` | false | Random distro per decky |
| `--archetype` / `-a` | — | Machine archetype slug |
| `--log-target` | — | `ip:port` RFC 5424 syslog target |
| `--log-file` | — | Log path inside containers |
| `--ipvlan` | false | IPvlan L2 instead of MACVLAN |
| `--dry-run` | false | Generate compose without starting |
| `--no-cache` | false | Force rebuild all images |
| `--config` / `-c` | — | INI config file path |


### Utilities

| Command | Description |
|---|---|
| `decnet services` | List all 25 registered honeypot service plugins |
| `decnet distros` | List OS distro profiles |
| `decnet archetypes` | List machine archetype profiles |

---

## REST API & Web Dashboard

### Start

Recommended (systemd-managed):

```bash
cp .env.example .env.local                          # edit JWT secret, ports, DB backend
sudo .venv/bin/decnet init                          # writes systemd units
sudo systemctl start "decnet-*.service"             # starts API, workers, bus
```

For development / quick runs, start the processes directly in the foreground:

```bash
decnet api start              # :8000
decnet web start              # :8080
```

### Authentication

All API endpoints (except `POST /api/v1/auth/login`) require a JWT bearer token. The health endpoint returns 401 without a token; liveness probes should accept 401 as healthy.

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

### Key API resource groups

| Prefix | Description |
|---|---|
| `/api/v1/auth/` | Login, change password, user management |
| `/api/v1/attackers/` | Attacker profiles, events, transcripts, exports |
| `/api/v1/identities/` | Clustered attacker identities |
| `/api/v1/campaigns/` | Attack campaigns |
| `/api/v1/deckies/` | Fleet state, deploy, lifecycle |
| `/api/v1/logs/` | Ingested log events, histogram |
| `/api/v1/topology/` | MazeNET topology CRUD and deployment |
| `/api/v1/canary/` | Canary token management |
| `/api/v1/bounty/` | Attacker reward/score board |
| `/api/v1/config/` | Runtime configuration |
| `/api/v1/health/` | API and worker health |
| `/api/v1/swarm/` | Swarm host management |
| `/api/v1/webhooks/` | Webhook management |
| `/api/v1/stream` | SSE live event stream |

### Database backends

| Backend | Driver | Use case |
|---|---|---|
| SQLite | `aiosqlite` | Single-host, dev, low-traffic |
| MySQL | `asyncmy` | Multi-host swarm, production |

Set `DECNET_DB_BACKEND=mysql` and configure `DECNET_DB_*` env vars.

---

## Swarm Mode

DECNET supports multi-host deployments. One host runs as **master** (API + intelligence stack); others run as **agents** (decky engine only).

Swarm management is handled through the REST API (`/api/v1/swarm/`). On each agent host, initialise and start the agent service:

```bash
# On agent host
sudo .venv/bin/decnet init
sudo systemctl start decnet-agent.service
```

Agents authenticate to the master with per-host mTLS client certificates. The master verifies each agent's certificate fingerprint against `SwarmHost.client_cert_fingerprint` — CA-issued but not fingerprint-pinned is rejected.

Package updates are distributed to agents via the REST API (`/api/v1/swarm/updater/`).

---

## Agent Mode

When a host runs as an agent (`DECNET_MODE=agent`), the master-only commands and the full REST API are disabled. The agent exposes a minimal internal API for the master to drive topology operations, heartbeat, and log forwarding.

```bash
DECNET_MODE=agent sudo .venv/bin/decnet init
sudo systemctl start decnet-agent.service
```

Cross-host log forwarding uses RFC 5425 syslog-over-TLS on port 6514 with mutual TLS. Plaintext syslog is only permitted on loopback.

---

## Service Bus

All internal events flow through the DECNET ServiceBus — a UNIX socket broker with NATS-style wildcard subscriptions.

```
topology.{id}.mutation.{state}
decky.{id}.state
attacker.observed
attacker.scored
attacker.session.started / ended
attacker.observation.{primitive}
identity.formed / merged / unmerged
campaign.formed / merged
credential.captured / reuse.detected
canary.{token_id}.triggered / placed / revoked
ttp.tagged / ttp.rule.fired.{technique_id}
orchestrator.traffic.{decky_id}
system.{worker}.health
```

Workers subscribe to topics and react in real time. The profiler, clusterer, correlator, canary cultivator, and TTP engine are all bus consumers.

---

## Attacker Intelligence

### Profiler

The attacker profiler runs as a background worker (or embedded in the API process via `DECNET_EMBED_PROFILER=true`). It consumes `attacker.observed` bus events and enriches each attacker record with:

- **Behavioural fingerprinting** — tool signatures, JA3 hashes, keystroke dynamics
- **Kill-chain phase detection** — reconnaissance, exploitation, lateral movement, exfiltration
- **Inter-probe timing analysis** — human vs. automated, scan speed estimation
- **BEHAVE primitives** — structured observation envelopes from the BEHAVE framework

### Clustering (UKC)

The UKC (Unified Knowledge Clustering) engine groups attacker sessions into identities based on behavioural similarity. It publishes `identity.formed` / `identity.merged` events to the bus.

### Correlation & Attribution

The correlation engine tracks relationships across identities and forms campaigns from groups of related attacker activity. Attribution state is tracked per identity primitive, with `identity_uuid` as the canonical primary key.

### GeoIP & ASN

All inbound attacker IPs are enriched with:
- Country, city, organisation (MaxMind-style database)
- ASN / network block (ip-to-asn dataset bundled under `decnet/asn/iptoasn/`)
- RIR allocation data

### Credentials

Captured credentials from SSH, SMB, RDP, and web honeypots are deduplicated and stored. Credential reuse across sessions triggers `credential.reuse.detected` bus events and is surfaced in the dashboard.

---

## MazeNET Topology

MazeNET is DECNET's visual network-of-networks canvas. It lets you design multi-subnet deception environments, deploy them as live decky fleets, and observe attacker movement across segments.

Topologies are managed through the REST API (`/api/v1/topology/`) and the web dashboard. Topologies are designed in the web dashboard with a drag-and-drop canvas. Each node is either a **decky** (managed honeypot) or an **observed entity** (read-only attacker-pool node). Canvas positions persist per topology in the dashboard.

Topology mutations are async — the API returns immediately and the deployment status is polled via `GET /api/v1/topology/{id}/mutations/latest` or streamed via SSE.

---

## Canary Tokens

Canary tokens are deception artefacts planted inside decky filesystems, emails, documents, and DNS responses. When triggered, they fire `canary.{token_id}.triggered` bus events and optionally call configured webhooks.

Canary tokens are managed through the REST API (`/api/v1/canary/`) and the web dashboard.

Token types include: URL, DNS, document (PDF), image, email link. After `decnet init`, install the JS obfuscation toolchain once:

```bash
decnet canary-install-toolchain
```

---

## TTP Tagging & Export

DECNET maps observed attacker behaviours to MITRE ATT&CK techniques using an inotify-backed rule store. Matched techniques are published as `ttp.tagged` bus events.

TTP tagging and exports are driven through the REST API (`/api/v1/ttp/`) and the web dashboard. Exports produce standard STIX 2.1 bundles and MISP events. DECNET uses the official MITRE ATT&CK STIX enterprise bundle and the CIRCL misp-stix converter. STIX custom extensions follow inter-DECNET round-trip semantics first; MISP/OpenCTI compatibility is secondary.

---

## Archetypes

Archetypes are pre-packaged machine identities. One slug sets services, preferred distros, and OS fingerprint all at once.

| Slug | Services | OS Fingerprint | Description |
|---|---|---|---|
| `deaddeck` | ssh | linux | Initial machine to be exploited. Real SSH container. |
| `windows-workstation` | smb, rdp | windows | Corporate Windows desktop |
| `windows-server` | smb, rdp, ldap | windows | Windows domain member |
| `domain-controller` | ldap, smb, rdp, llmnr | windows | Active Directory DC |
| `linux-server` | ssh, http | linux | General-purpose Linux host |
| `web-server` | http, ftp | linux | Public-facing web host |
| `database-server` | mysql, postgres, redis | linux | Data tier host |
| `mail-server` | smtp, pop3, imap | linux | SMTP/IMAP/POP3 relay |
| `file-server` | smb, ftp, ssh | linux | SMB/FTP/SFTP storage node |
| `printer` | snmp, ftp | embedded | Network-attached printer |
| `iot-device` | mqtt, snmp, telnet | embedded | Embedded/IoT device |
| `industrial-control` | conpot, snmp | embedded | ICS/SCADA node |
| `voip-server` | sip | linux | SIP PBX / VoIP gateway |
| `monitoring-node` | snmp, ssh | linux | Infrastructure monitoring host |
| `devops-host` | docker_api, ssh, k8s | linux | CI/CD / container host |

```bash
sudo decnet deploy --deckies 4 --archetype windows-workstation
```

---

## Services

25 honeypot services are registered out of the box.

| Slug | Ports | Protocol / Role |
|---|---|---|
| `ssh` | 22 | SSH (Cowrie honeypot) |
| `http` | 80, 443 | HTTP/HTTPS web server |
| `ftp` | 21 | FTP file transfer |
| `tftp` | 69 | TFTP (trivial file transfer) |
| `smb` | 445, 139 | SMB/CIFS file shares |
| `rdp` | 3389 | Remote Desktop Protocol |
| `telnet` | 23 | Telnet remote access |
| `vnc` | 5900 | VNC remote desktop |
| `smtp` | 25, 587 | SMTP mail relay |
| `imap` | 143, 993 | IMAP mail access |
| `pop3` | 110, 995 | POP3 mail access |
| `ldap` | 389, 636 | LDAP / Active Directory |
| `llmnr` | 5355, 5353 | LLMNR / mDNS (Windows name resolution) |
| `mysql` | 3306 | MySQL database |
| `postgres` | 5432 | PostgreSQL database |
| `mssql` | 1433 | Microsoft SQL Server |
| `mongodb` | 27017 | MongoDB document store |
| `redis` | 6379 | Redis key-value store |
| `elasticsearch` | 9200 | Elasticsearch REST API |
| `mqtt` | 1883 | MQTT IoT broker |
| `snmp` | 161 | SNMP network management |
| `sip` | 5060 | SIP VoIP protocol |
| `k8s` | 6443, 8080 | Kubernetes API server |
| `docker_api` | 2375, 2376 | Docker Remote API |
| `conpot` | 502, 161, 80 | ICS/SCADA (Modbus, S7, DNP3) |

### Per-service persona config

```ini
[decky-01.ssh]
ssh_version    = OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
kernel_version = 5.15.0-91-generic
users          = root:toor,admin:admin123

[decky-01.http]
server_header = nginx/1.18.0
fake_app      = wordpress

[decky-winbox.smb]
workgroup   = CORP
server_name = WINSRV-DC01
os_version  = Windows Server 2016
```

Accepted keys per service:

| Service | Keys |
|---|---|
| `ssh` | `ssh_version`, `kernel_version`, `users` |
| `http` | `server_header`, `response_code`, `fake_app` |
| `smtp` | `smtp_banner`, `smtp_mta` |
| `smb` | `workgroup`, `server_name`, `os_version` |
| `rdp` | `os_version`, `build` |
| `mysql` | `mysql_version`, `mysql_banner` |
| `redis` | `redis_version` |
| `postgres` | `pg_version` |
| `mongodb` | `mongo_version` |
| `elasticsearch` | `es_version`, `cluster_name` |
| `ldap` | `base_dn`, `domain` |
| `snmp` | `snmp_community`, `sys_descr`, `snmp_archetype` |
| `mqtt` | `mqtt_version` |
| `sip` | `sip_server`, `sip_domain` |
| `k8s` | `k8s_version` |
| `docker_api` | `docker_version` |
| `vnc` | `vnc_version` |
| `mssql` | `mssql_version` |

### Bring-your-own service (BYOS)

```ini
[custom-myapp]
binary = my-docker-image:latest
exec   = /usr/bin/myapp -p 9999
ports  = 9999
```

---

## OS Fingerprint Spoofing

DECNET injects Linux kernel TCP/IP `sysctls` into each decky's base container so that active OS detection (e.g. `nmap -O`) returns the expected OS.

| Family | TTL | `tcp_syn_retries` | Notes |
|---|---|---|---|
| `linux` | 64 | 6 | Default |
| `windows` | 128 | 2 | + 8 MB recv buffer |
| `bsd` | 64 | 6 | FreeBSD / macOS-style |
| `embedded` | 255 | 3 | Printers, IoT, PLCs |
| `cisco` | 255 | 2 | Network devices |

```ini
[decky-winbox]
services = rdp, smb, mssql
nmap_os  = windows
```

Priority: explicit `nmap_os=` > archetype default > `linux`.

---

## Distro Profiles

| Slug | Docker Image | Display Name |
|---|---|---|
| `debian` | `debian:bookworm-slim` | Debian 12 (Bookworm) |
| `ubuntu22` | `ubuntu:22.04` | Ubuntu 22.04 LTS (Jammy) |
| `ubuntu20` | `ubuntu:20.04` | Ubuntu 20.04 LTS (Focal) |
| `rocky9` | `rockylinux:9-minimal` | Rocky Linux 9 |
| `centos7` | `centos:7` | CentOS 7 |
| `alpine` | `alpine:3.19` | Alpine Linux 3.19 |
| `fedora` | `fedora:39` | Fedora 39 |
| `kali` | `kalilinux/kali-rolling` | Kali Linux (Rolling) |
| `arch` | `archlinux:latest` | Arch Linux |

When no distro is specified, DECNET cycles through all profiles in round-robin to maximise heterogeneity automatically.

---

## Config File

```bash
decnet deploy --config mynet.ini --dry-run
sudo decnet deploy --config mynet.ini --log-target 192.168.1.200:5140
```

```ini
[general]
net        = 192.168.1.0/24
gw         = 192.168.1.1
interface  = eth0
log_target = 192.168.1.200:5140

[decky-01]
ip       = 192.168.1.110
services = ssh, http
nmap_os  = linux

[decky-01.ssh]
ssh_version    = OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
kernel_version = 5.15.0-91-generic
users          = root:toor,admin:admin123

[decky-01.http]
server_header = nginx/1.18.0
fake_app      = wordpress

[corp-workstations]
archetype = windows-workstation
amount    = 10

[custom-myapp]
binary = my-image:latest
exec   = /usr/bin/myapp -p 9999
ports  = 9999
```

#### `[general]`

| Key | Required | Description |
|---|---|---|
| `net` | Yes | Subnet CIDR |
| `gw` | Yes | Gateway IP |
| `interface` | No | Host NIC; auto-detected if absent |
| `log_target` | No | `ip:port` for RFC 5424 syslog |

#### Decky sections

| Key | Required | Description |
|---|---|---|
| `ip` | No | Static IP; auto-allocated if absent |
| `services` | See note | Comma-separated service slugs |
| `archetype` | See note | Sets services + nmap_os unless overridden |
| `nmap_os` | No | `linux` / `windows` / `bsd` / `embedded` / `cisco` |
| `amount` | No | Spawn N deckies from this block; cannot combine with `ip=` |

> One of `services=`, `archetype=`, or `--randomize-services` is required per decky.

See [`test-full.ini`](test-full.ini) for a complete example covering all 25 services.

---

## Environment Configuration

Copy `.env.example` to `.env.local`:

```ini
# API
DECNET_API_HOST=0.0.0.0
DECNET_API_PORT=8000
DECNET_JWT_SECRET=supersecretkey12345

# Web dashboard
DECNET_WEB_HOST=0.0.0.0
DECNET_WEB_PORT=8080
DECNET_ADMIN_USER=admin
DECNET_ADMIN_PASSWORD=admin

# Database
DECNET_DB_BACKEND=sqlite          # or mysql
DECNET_DB_POOL_SIZE=20
DECNET_DB_MAX_OVERFLOW=40

# Log ingestion
DECNET_INGEST_LOG_FILE=/var/log/decnet/decnet.log

# Tracing (optional — requires pip install -e ".[tracing]")
DECNET_TRACING=false

# Deployment mode
DECNET_MODE=master                 # or agent
```

---

## Logging

All attacker interactions are forwarded off the decoy network to an isolated logging sink. Cross-host log forwarding uses RFC 5425 syslog-over-TLS on port 6514 with mTLS. Plaintext syslog is only permitted on loopback.

```bash
sudo decnet deploy --config mynet.ini --log-target 192.168.1.200:5140
```

Or in `[general]`:

```ini
log_target = 192.168.1.200:5140
```

### Log target health check

Before deployment, DECNET probes the log target and warns if unreachable. Deployment continues regardless.

---

## Network Drivers

### MACVLAN (default)

Each decky gets a unique MAC address, appearing as a distinct physical machine. Requires promiscuous mode on the host NIC.

DECNET automatically creates a `decnet_macvlan0` host-side hairpin interface so status checks and log collection continue to work from the master host.

### IPvlan L2 (`--ipvlan`)

Use when MACVLAN is not available — typically on WiFi where the AP filters non-registered MACs. Shares the host MAC; gives each decky a unique IP only.

```bash
sudo decnet deploy --interface wlp6s0 --ipvlan --deckies 3 --randomize-services
```

---

## Writing a Custom Service Plugin

1. Create `decnet/services/myservice.py`:

```python
from decnet.services.base import BaseService

class MyService(BaseService):
    name = "myservice"
    ports = [1234]
    default_image = "my-docker-image:latest"

    def compose_fragment(self, decky_name, log_target=None, service_cfg=None):
        cfg = service_cfg or {}
        return {
            "image": self.default_image,
            "container_name": f"{decky_name}-myservice",
            "restart": "unless-stopped",
            "environment": {
                "MY_BANNER": cfg.get("banner", "default banner"),
            },
        }
```

2. The registry auto-discovers all `BaseService` subclasses — no registration step needed.

3. For services requiring a custom Dockerfile, set `default_image = "build"` and override `dockerfile_context()`. The composer injects `BASE_IMAGE` as a build arg:

```dockerfile
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}
```

---

## Development & Testing

```bash
pip install -e ".[dev]"
source .311/bin/activate
pytest tests/                  # ~5050 tests, ~2 min
```

Scoped runs (skip heavy categories):

```bash
pytest tests/unit/             # fast unit tests only
pytest tests/api/              # API contract tests
```

The test suite is split into several categories controlled by markers:

| Marker | How to run | Description |
|---|---|---|
| _(default)_ | `pytest tests/` | Unit + integration tests |
| `fuzz` | `pytest -m fuzz` | Hypothesis fuzz tests |
| `stress` | `pytest -m stress tests/stress/` | Locust throughput tests |
| `bench` | `pytest -m bench` | pytest-benchmark micro-benchmarks |
| `live` | `pytest -m live` | Live subprocess service tests |
| `live_docker` | `DECNET_LIVE_DOCKER=1 pytest -m live_docker` | Live Docker tests |

### Stress Testing

A [Locust](https://locust.io)-based stress test suite lives in `tests/stress/`.

```bash
pytest -m stress tests/stress/ -v -x -n0 -s
STRESS_USERS=2000 STRESS_SPAWN_RATE=200 STRESS_DURATION=120 \
  pytest -m stress tests/stress/ -v -x -n0 -s

# Standalone Locust web UI
locust -f tests/stress/locustfile.py --host http://localhost:8000
```

| Env var | Default | Description |
|---|---|---|
| `STRESS_USERS` | `500` | Total simulated users |
| `STRESS_SPAWN_RATE` | `50` | Users spawned per second |
| `STRESS_DURATION` | `60` | Test duration in seconds |
| `STRESS_WORKERS` | CPU count (max 4) | Uvicorn workers |
| `STRESS_MIN_RPS` | `500` | Minimum RPS to pass |
| `STRESS_MAX_P99_MS` | `200` | Maximum p99 latency (ms) to pass |

#### Measured baseline (MySQL backend, asyncmy driver)

| Metric | 500u, tracing on | 1500u, tracing on | 1500u, tracing **off** | 1500u, off, **12 workers** |
|---|---|---|---|---|
| Throughput (RPS) | ~960 | ~880 | ~990 | ~1,585 |
| Median (p50) | 100 ms | 690 ms | 340 ms | 700 ms |
| p95 | 1.9 s | 6.5 s | 5.7 s | 2.7 s |
| p99 | 2.9 s | 9.5 s | 8.4 s | 4.2 s |
| Failures | 0 | 0 | 0 | 0 |

Tuning notes:

- **Tracing off** halves p50 at 1500 users (690 → 340 ms).
- **12 workers** scales RPS ~1.6× over one worker. DB-bound — MySQL `max_connections` needs bumping beyond the default 151 for multi-worker load.
- **Router-level TTL caches** on hot count/stats endpoints collapse concurrent duplicate DB queries — essential for high single-worker RPS.
- **Python 3.14 is not supported** — the reworked GC segfaults under heavy concurrent async load (`_PyGC_Collect` / `mark_all_reachable`). Use Python 3.11–3.13.

#### System tuning

Under 500+ concurrent users, the default Linux open file limit (1024) causes `OSError: Too many open files`:

```bash
ulimit -n 65536                   # session
# or permanent via /etc/security/limits.conf:
*  soft  nofile  65536
*  hard  nofile  65536
```

For systemd units: `LimitNOFILE=65536`.

---

# AI Disclosure

This project has been made with lots, and I mean lots of help from AIs. While most of the design was made by me, most of the coding was done by AI models.

Nevertheless, this project will be kept under high scrutiny by humans.
