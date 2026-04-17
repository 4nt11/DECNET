# DECNET

A honeypot deception network framework. Spin up a fleet of fake machines — called **deckies** — that appear as real, heterogeneous LAN hosts to anyone scanning the network. Each decky gets its own MAC address, IP, hostname, services, OS fingerprint, and log pipeline.

Attackers probe the network, DECNET traps every interaction, and you watch from a safe, isolated logging stack.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Archetypes](#archetypes)
- [Services](#services)
- [OS Fingerprint Spoofing](#os-fingerprint-spoofing)
- [Distro Profiles](#distro-profiles)
- [Config File](#config-file)
- [Logging](#logging)
- [Network Drivers](#network-drivers)
- [Architecture](#architecture)
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
         ▼ all interactions forwarded via RFC 5424 syslog
  ┌──────────────────────┐
  │   ELK / SIEM stack   │  (isolated network — not reachable from decoys)
  └──────────────────────┘
```

Each decky is a small cluster of Docker containers sharing one network namespace:

- **Base container** — holds the MACVLAN IP, sets TCP/IP stack sysctls for OS fingerprint spoofing, runs `sleep infinity`.
- **Service containers** — one per honeypot service, all sharing the base's network so they appear to come from the same IP.

From the outside a decky looks identical to a real machine: it has its own MAC address (assigned by MACVLAN), its own IP, its own hostname, and its TCP/IP stack behaves like the OS it is pretending to be.

---

## Requirements

- Linux host (bare metal or VM — WSL has MACVLAN limitations)
- Docker Engine 24+
- Python 3.11+
- Root / `sudo` for network setup (MACVLAN creation, host interface config)
- NIC in promiscuous mode for MACVLAN (or use `--ipvlan` on WiFi)

---

## Installation

```bash
git clone https://git.resacachile.cl/anti/DECNET
cd DECNET
pip install -e .
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

### Deploy a specific role

```bash
sudo decnet deploy --mode unihost --deckies 3 --archetype windows-workstation
```

### Deploy from a config file

```bash
sudo decnet deploy --config test-full.ini
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

## CLI Reference

### `decnet deploy`

| Flag | Default | Description |
|---|---|---|
| `--mode` | `unihost` | Deployment mode: `unihost` or `swarm` |
| `--deckies` / `-n` | — | Number of deckies to deploy (required without `--config`) |
| `--interface` / `-i` | auto-detected | Host NIC to attach MACVLAN to |
| `--subnet` | auto-detected | LAN subnet CIDR, e.g. `192.168.1.0/24` |
| `--ip-start` | auto | First IP to assign to deckies |
| `--services` | — | Comma-separated service slugs, e.g. `ssh,smb,rdp` |
| `--randomize-services` | false | Assign random services to each decky |
| `--distro` | auto-cycled | Comma-separated distro slugs, e.g. `debian,ubuntu22` |
| `--randomize-distros` | false | Assign a random distro to each decky |
| `--archetype` / `-a` | — | Machine archetype slug (sets services + OS family automatically) |
| `--log-target` | — | Forward logs to `ip:port` (RFC 5424 syslog) |
| `--log-file` | — | Write logs to this path inside containers |
| `--ipvlan` | false | Use IPvlan L2 instead of MACVLAN (required on WiFi) |
| `--dry-run` | false | Generate compose file without starting containers |
| `--no-cache` | false | Force rebuild all images |
| `--config` / `-c` | — | Path to INI config file |

### `decnet status`

Print a table of all deployed deckies, their IPs, services, hostnames, and container states.

### `decnet teardown`

| Flag | Description |
|---|---|
| `--all` | Tear down all deckies and remove the MACVLAN network |
| `--id <name>` | Stop and remove a single decky by name |

### `decnet services`

List all registered honeypot service plugins with their ports and Docker images.

### `decnet distros`

List all available OS distro profiles.

### `decnet archetypes`

List all machine archetype profiles with their default services and descriptions.

---

## Archetypes

Archetypes are pre-packaged machine identities. One slug sets services, preferred distros, and OS fingerprint all at once — no need to think about individual components.

| Slug | Services | OS Fingerprint | Description |
|---|---|---|---|
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

#### CLI

```bash
sudo decnet deploy --deckies 4 --archetype windows-workstation
```

#### INI

```ini
[corp-workstations]
archetype = windows-workstation
amount    = 4

[win-fileserver]
services   = ftp
nmap_os    = windows
os_version = Windows Server 2019

[dbsrv01]
ip       = 192.168.1.112
services = mysql, http
nmap_os  = linux

[dbsrv01.http]
server_header = Apache/2.4.54 (Debian)
response_code = 200
fake_app      = wordpress

[dbsrv01.mysql]
mysql_version = 5.7.38-log
mysql_banner  = MySQL Community Server

```

---

## Services

25 honeypot services are registered out of the box. Use their slug in `--services` or `services=` in a config file.

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

List live at any time with `decnet services`.

### Per-service persona config

Most services accept persona configuration to make honeypot responses more convincing. Config is passed via INI subsections (`[decky-name.service]`) or the `service_config` field in code.

```ini
[decky-webmail.http]
server_header = Apache/2.4.54 (Debian)
fake_app      = wordpress

[decky-winbox.smb]
workgroup   = CORP
server_name = WINSRV-DC01
os_version  = Windows Server 2016

[decky-legacy.ssh]
ssh_version    = OpenSSH_7.4p1 Debian-10+deb9u7
kernel_version = 4.9.0-19-amd64
users          = root:root,admin:password
```

### Bring-your-own service (BYOS)

Drop in a custom service definition using the `custom-` prefix in an INI config:

```ini
[custom-myapp]
binary = my-docker-image:latest
exec   = /usr/bin/myapp -p 9999
ports  = 9999
```

The service is registered at runtime and can be referenced as `myapp` in any decky's `services=` list.

---

## OS Fingerprint Spoofing

DECNET injects Linux kernel TCP/IP stack parameters (`sysctls`) into each decky's base container so that active OS detection (e.g. `nmap -O`) returns the expected OS rather than "Linux".

The most important probe nmap uses is the IP TTL. Secondary tuning covers TCP SYN retry behaviour and initial receive window size.

### OS families

| Family | TTL | `tcp_syn_retries` | Notes |
|---|---|---|---|
| `linux` | 64 | 6 | Default |
| `windows` | 128 | 2 | + 8 MB recv buffer |
| `bsd` | 64 | 6 | FreeBSD / macOS-style |
| `embedded` | 255 | 3 | Printers, IoT, PLCs |
| `cisco` | 255 | 2 | Network devices |

Because service containers share the base container's network namespace (`network_mode: service:<base>`), the spoofed stack applies to **all** traffic from the decky — no per-service config needed.

### Automatic via archetype

Archetypes set `nmap_os` automatically. A `windows-workstation` decky comes with TTL 128 out of the box.

### Explicit in INI

```ini
[decky-winbox]
services = rdp, smb, mssql
nmap_os  = windows          # also accepts nmap-os=

[decky-iot]
services = mqtt, snmp
nmap_os  = embedded

[decky-legacy]
services = telnet, vnc, ssh
nmap_os  = bsd
```

Priority: **explicit `nmap_os=`** > archetype default > `linux`.

### Verify with nmap

```bash
sudo nmap -O 192.168.1.114    # should report Windows
sudo nmap -O 192.168.1.117    # should report embedded / network device
```

> **Note:** Linux kernel containers cannot perfectly replicate every nmap OS probe (sequence generation, ECN flags, etc.). TTL and TCP window tuning cover the most reliable detection vectors. Full impersonation would require a userspace TCP stack.

---

## Distro Profiles

The distro controls which Docker base image is used for the IP-holding base container, giving each decky a different OS identity at the image layer and varying the hostname style.

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

```bash
# Explicit single distro
sudo decnet deploy --deckies 3 --services ssh --distro rocky9

# Mix of distros (cycled)
sudo decnet deploy --deckies 6 --services ssh --distro debian,ubuntu22,rocky9

# Fully random
sudo decnet deploy --deckies 5 --randomize-services --randomize-distros
```

---

## Config File

For anything beyond a handful of deckies, use an INI config file. It gives you per-decky IPs, per-service personas, archetype pools, and custom service definitions all in one place.

```bash
decnet deploy --config mynet.ini --dry-run
sudo decnet deploy --config mynet.ini --log-target 192.168.1.200:5140
```

### Structure

```ini
# ── Global settings ───────────────────────────────────────────────────────────

[general]
net        = 192.168.1.0/24      # subnet CIDR
gw         = 192.168.1.1         # gateway IP
interface  = eth0                # host NIC (optional, auto-detected if omitted)
log_target = 192.168.1.200:5140  # syslog forwarding target (optional)

# ── Decky sections ────────────────────────────────────────────────────────────

[decky-01]
ip       = 192.168.1.110        # optional; auto-allocated if omitted
services = ssh, http             # comma-separated service slugs
nmap_os  = linux                 # OS fingerprint family (optional, default: linux)

# ── Per-service persona ───────────────────────────────────────────────────────

[decky-01.ssh]
ssh_version    = OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
kernel_version = 5.15.0-91-generic
users          = root:toor,admin:admin123

[decky-01.http]
server_header = nginx/1.18.0
fake_app      = wordpress

# ── Archetype shorthand ───────────────────────────────────────────────────────

[corp-workstations]
archetype = windows-workstation  # sets services, distros, and nmap_os automatically
amount    = 10                   # spawn 10 deckies from this definition

# ── Bring-your-own service ────────────────────────────────────────────────────

[custom-myapp]
binary = my-image:latest
exec   = /usr/bin/myapp -p 9999
ports  = 9999
```

### Field reference

#### `[general]`

| Key | Required | Description |
|---|---|---|
| `net` | Yes | Subnet CIDR for the decoy LAN |
| `gw` | Yes | Gateway IP |
| `interface` | No | Host NIC; auto-detected if absent |
| `log_target` | No | `ip:port` for RFC 5424 syslog forwarding |

#### Decky sections

| Key | Required | Description |
|---|---|---|
| `ip` | No | Static IP; auto-allocated from subnet if absent |
| `services` | See note | Comma-separated service slugs |
| `archetype` | See note | Archetype slug; sets services + nmap_os unless overridden |
| `nmap_os` | No | OS fingerprint family: `linux` / `windows` / `bsd` / `embedded` / `cisco` |
| `amount` | No | Spawn N deckies from this block (default: 1); cannot combine with `ip=` |

> One of `services=`, `archetype=`, or `--randomize-services` is required per decky.

#### Per-service subsections `[decky-name.service]`

Key/value pairs are passed directly to the service plugin as persona config. Common keys:

| Service | Accepted keys |
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
| `snmp` | `snmp_community`, `sys_descr`, `snmp_archetype` (picks predefined sysDescr for `water_plant`, `hospital`, etc.) |
| `mqtt` | `mqtt_version` |
| `sip` | `sip_server`, `sip_domain` |
| `k8s` | `k8s_version` |
| `docker_api` | `docker_version` |
| `vnc` | `vnc_version` |
| `mssql` | `mssql_version` |

When using `amount=`, a subsection like `[group-name.ssh]` automatically propagates to all expanded deckies (`group-name-01`, `group-name-02`, …).

### Full example

See [`test-full.ini`](test-full.ini) — covers all 25 services across 10 role-themed deckies with per-service personas, archetype pools, OS fingerprint assignments, and inline comments explaining each choice.

---

## Environment Configuration (.env)

DECNET supports loading configuration from `.env.local` and `.env` files located in the project root. This is useful for securing secrets like the JWT key and configuring default ports without passing flags every time.

An example `.env.example` is provided:

```ini
# API Options
DECNET_API_HOST=0.0.0.0
DECNET_API_PORT=8000
DECNET_JWT_SECRET=supersecretkey12345
DECNET_INGEST_LOG_FILE=/var/log/decnet/decnet.log

# Web Dashboard Options
DECNET_WEB_HOST=0.0.0.0
DECNET_WEB_PORT=8080
DECNET_ADMIN_USER=admin
DECNET_ADMIN_PASSWORD=admin

# Database pool tuning (applies to both SQLite and MySQL)
DECNET_DB_POOL_SIZE=20       # base pool connections (default: 20)
DECNET_DB_MAX_OVERFLOW=40    # extra connections under burst (default: 40)
```

Copy `.env.example` to `.env.local` and modify it to suit your environment.

---

## Logging

All attacker interactions are forwarded off the decoy network to an isolated logging sink. The log pipeline lives on a separate internal Docker bridge (`decnet_logs`) that is not reachable from the fake LAN.

### Syslog forwarding (RFC 5424)

```bash
sudo decnet deploy --config mynet.ini --log-target 192.168.1.200:5140
```

Or in `[general]`:

```ini
log_target = 192.168.1.200:5140
```

### File logging

```bash
sudo decnet deploy --config mynet.ini --log-file /var/log/decnet/decnet.log
```

The log directory is bind-mounted into every service container. Log entries follow RFC 5424 syslog format.

### Log target health check

Before deployment, DECNET probes the log target and warns if it is unreachable:

```
Warning: log target 192.168.1.200:5140 is unreachable. Logs will be lost if it stays down.
```

Deployment continues regardless — the log target can come up later.

---

## Network Drivers

### MACVLAN (default)

Each decky gets a unique MAC address assigned by the kernel, making it appear as a distinct physical machine on the LAN. Requires the host NIC to support promiscuous mode.

```bash
sudo decnet deploy --interface eth0 --deckies 5 --randomize-services
```

**Known limitation:** The host cannot communicate directly with its own MACVLAN children by default. DECNET automatically creates a `decnet_macvlan0` host-side interface as a hairpin workaround so that `decnet status` and log collection continue to work from the host.

### IPvlan L2 (`--ipvlan`)

Use IPvlan L2 when MACVLAN is not available — typically on WiFi interfaces where the access point filters non-registered MACs. IPvlan shares the host MAC and gives each decky a unique IP only.

```bash
sudo decnet deploy --interface wlp6s0 --ipvlan --deckies 3 --randomize-services
```

---

## Architecture

```
decnet/
├── cli.py            # Typer CLI entry point; builds DecnetConfig from flags/INI
├── config.py         # Pydantic models: DeckyConfig, DecnetConfig; state persistence
├── composer.py       # Generates docker-compose.yml from DecnetConfig
├── deployer.py       # Docker SDK: bring-up, teardown, status
├── network.py        # MACVLAN/IPvlan creation, IP allocation, hairpin interface
├── archetypes.py     # Machine archetype profiles (14 built-in)
├── distros.py        # OS distro profiles (9 built-in), hostname generation
├── os_fingerprint.py # TCP/IP sysctl profiles per OS family for nmap spoofing
├── ini_loader.py     # INI config file parser
├── custom_service.py # Bring-your-own service runtime registration
├── services/
│   ├── base.py       # BaseService ABC — contract every plugin must implement
│   ├── registry.py   # Auto-discovers and registers all BaseService subclasses
│   └── *.py          # 25 individual honeypot service plugins
├── logging/
│   ├── forwarder.py  # RFC 5424 syslog UDP forwarder
│   ├── file_handler.py
│   └── syslog_formatter.py
└── templates/        # Dockerfiles and service entrypoint scripts
```

### Container model

```
decky-01  (base)        ← MACVLAN IP owner; sleep infinity; sysctls applied here
  ├─ decky-01-ssh       ← network_mode: service:decky-01  (shares IP + MAC)
  ├─ decky-01-http      ← network_mode: service:decky-01
  └─ decky-01-smb       ← network_mode: service:decky-01
```

Service containers carry no network config of their own. From the outside, every port on a decky appears to belong to a single machine.

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

2. The registry auto-discovers all `BaseService` subclasses at import time — no registration step needed.

3. Use it immediately:

```bash
decnet services                               # myservice appears in the list
sudo decnet deploy --deckies 2 --services myservice
```

For services that require a custom Dockerfile, set `default_image = "build"` and override `dockerfile_context()` to return the path to your build context directory. The composer injects `BASE_IMAGE` as a build arg so your Dockerfile picks up the correct distro image automatically:

```dockerfile
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}
...
```

---

## Development & Testing

```bash
pip install -e .
python -m pytest          # 478 tests, < 1 second
```

The test suite covers:

| File | What it tests |
|---|---|
| `test_composer.py` | Compose generation, BASE_IMAGE injection, distro heterogeneity |
| `test_os_fingerprint.py` | OS sysctl profiles, compose injection, archetype coverage, CLI propagation |
| `test_ini_loader.py` | INI parsing, subsection propagation, custom services, `nmap_os` |
| `test_services.py` | Per-service persona config, compose fragments |
| `test_network.py` | IP allocation, range calculation |
| `test_log_file_mount.py` | Log directory bind-mount injection |
| `test_syslog_formatter.py` | RFC 5424 syslog formatting |
| `test_archetypes.py` | Archetype validation and field correctness |
| `test_cli_service_pool.py` | CLI service resolution |

Every new feature requires passing tests before merging.

### Stress Testing

A [Locust](https://locust.io)-based stress test suite lives in `tests/stress/`. It hammers every API endpoint with realistic traffic patterns to find throughput ceilings and latency degradation.

```bash
# Run via pytest (starts its own server)
pytest -m stress tests/stress/ -v -x -n0 -s

# Crank it up
STRESS_USERS=2000 STRESS_SPAWN_RATE=200 STRESS_DURATION=120 pytest -m stress tests/stress/ -v -x -n0 -s

# Standalone Locust web UI against a running server
locust -f tests/stress/locustfile.py --host http://localhost:8000
```

| Env var | Default | Description |
|---|---|---|
| `STRESS_USERS` | `500` | Total simulated users |
| `STRESS_SPAWN_RATE` | `50` | Users spawned per second |
| `STRESS_DURATION` | `60` | Test duration in seconds |
| `STRESS_WORKERS` | CPU count (max 4) | Uvicorn workers for the test server |
| `STRESS_MIN_RPS` | `500` | Minimum RPS to pass baseline test |
| `STRESS_MAX_P99_MS` | `200` | Maximum p99 latency (ms) to pass |
| `STRESS_SPIKE_USERS` | `1000` | Users for thundering herd test |
| `STRESS_SUSTAINED_USERS` | `200` | Users for sustained load test |

#### System tuning: open file limit

Under heavy load (500+ concurrent users), the server will exhaust the default Linux open file limit (`ulimit -n`), causing `OSError: [Errno 24] Too many open files`. Most distros default to **1024**, which is far too low for stress testing or production use.

**Before running stress tests:**

```bash
# Check current limit
ulimit -n

# Bump for this shell session
ulimit -n 65536
```

**Permanent fix** — add to `/etc/security/limits.conf`:

```
*  soft  nofile  65536
*  hard  nofile  65536
```

Or for systemd-managed services, add `LimitNOFILE=65536` to the unit file.

> This applies to production deployments too — any server handling hundreds of concurrent connections needs a raised file descriptor limit.

# AI Disclosure

This project has been made with lots, and I mean lots of help from AIs. While most of the design was made by me, most of the coding was done by AI models.

Nevertheless, this project will be kept under high scrutiny by humans.
