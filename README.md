# DECNET

A honeypot/deception network framework. Deploys fake machines (**deckies**) with realistic services (SSH, SMB, RDP, FTP, HTTP) that appear as real LAN hosts — complete with their own MACs and IPs — to lure, detect, and profile attackers. All interactions are forwarded to an isolated logging pipeline (ELK / SIEM).

```
attacker ──► decoy network (deckies)
                   │
                   └──► log forwarder ──► isolated SIEM (ELK)
```

---

## Requirements

- Python ≥ 3.11
- Docker + Docker Compose
- Root / `sudo` for MACVLAN networking (bare metal or VM recommended; WSL has known limitations)

---

## Install

```bash
pip install -e .
```

---

## Usage

```bash
# List available honeypot service plugins
decnet services

# Dry-run — generate compose file, no containers started
decnet deploy --mode unihost --deckies 3 --randomize-services --dry-run

# Deploy 5 deckies with random services
sudo decnet deploy --mode unihost --deckies 5 --interface eth0 --randomize-services

# Deploy with specific services and log forwarding
sudo decnet deploy --mode unihost --deckies 3 --services ssh,smb --log-target 192.168.1.5:5140

# Deploy from an INI config file
sudo decnet deploy --config decnet.ini

# Status
decnet status

# Teardown
sudo decnet teardown --all
sudo decnet teardown --id decky-01
```

### Key flags

| Flag | Description |
|---|---|
| `--mode` | `unihost` (single host) or `swarm` (multi-host) |
| `--deckies N` | Number of fake machines to spin up |
| `--interface` | Host NIC (auto-detected if omitted) |
| `--subnet` | LAN subnet CIDR (auto-detected if omitted) |
| `--ip-start` | First decky IP (auto if omitted) |
| `--services` | Comma-separated list: `ssh,smb,rdp,ftp,http` |
| `--randomize-services` | Assign random service mix to each decky |
| `--log-target` | Forward logs to `ip:port` (e.g. Logstash) |
| `--dry-run` | Generate compose file without starting containers |
| `--no-cache` | Force rebuild all images |
| `--config` | Path to INI config file |

---

## Deployment Modes

**UNIHOST** — one real host spins up _n_ deckies via Docker Compose. Simplest setup, single machine.

**SWARM (MULTIHOST)** — _n_ real hosts each running deckies. Orchestrated via Ansible or similar tooling.

---

## Architecture

- **Containers**: Docker Compose with `debian:bookworm-slim` as the default base image. Mixing Ubuntu, CentOS, and other distros is encouraged to make the decoy network look heterogeneous.
- **Networking**: MACVLAN/IPVLAN — each decky gets its own MAC and IP, appearing as a distinct real machine on the LAN.
- **Log pipeline**: Logstash → ELK stack → SIEM on an isolated network unreachable from the decoy network.
- **Services**: Plugin-based registry (`decnet/services/`). Each plugin declares its ports, default image, and container config.

```
decnet/
├── cli.py            # Typer CLI — deploy, status, teardown, services
├── config.py         # Pydantic models (DecnetConfig, DeckyConfig)
├── composer.py       # Docker Compose YAML generator
├── deployer.py       # Container lifecycle management
├── network.py        # IP allocation, interface/subnet detection
├── ini_loader.py     # INI config file support
├── logging/
│   └── forwarder.py  # Log target probe + forwarding
└── services/
    ├── registry.py   # Plugin registry
    ├── ssh.py
    ├── smb.py
    ├── rdp.py
    ├── ftp.py
    └── http.py
```

---

## INI Config

You can describe a fully custom decoy fleet in an INI file instead of CLI flags:

```ini
[global]
interface = eth0
log_target = 192.168.1.5:5140

[decky-01]
services = ssh,smb
base_image = debian:bookworm-slim
hostname = DESKTOP-A1B2C3

[decky-02]
services = rdp,http
base_image = ubuntu:22.04
hostname = WIN-SERVER-02
```

```bash
sudo decnet deploy --config decnet.ini
```

---

## Adding a Service Plugin

1. Create `decnet/services/yourservice.py` implementing the `BaseService` interface.
2. Register it in `decnet/services/registry.py`.
3. Verify with `decnet services`.
