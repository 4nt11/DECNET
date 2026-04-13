# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (dev)
pip install -e .

# List registered service plugins
decnet services

# Dry-run (generates compose, no containers)
decnet deploy --mode unihost --deckies 3 --randomize-services --dry-run

# Full deploy (requires root for MACVLAN)
sudo decnet deploy --mode unihost --deckies 5 --interface eth0 --randomize-services
sudo decnet deploy --mode unihost --deckies 3 --services ssh,smb --log-target 192.168.1.5:5140

# Status / teardown
decnet status
sudo decnet teardown --all
sudo decnet teardown --id decky-01
```

## Project Overview

DECNET is a honeypot/deception network framework. It deploys fake machines (called **deckies**) with realistic services (RDP, SMB, SSH, FTP, etc.) to lure and profile attackers. All attacker interactions are aggregated to an isolated logging network (ELK stack / SIEM).

## Deployment Models

**UNIHOST** — one real host spins up _n_ deckies via a container orchestrator. Simpler, single-machine deployment.

**SWARM (MULTIHOST)** — _n_ real hosts each running deckies. Orchestrated via Ansible/sshpass or similar tooling.

## Core Technology Choices

- **Containers**: Docker Compose is the starting point but other orchestration frameworks should be evaluated if they serve the project better. `debian:bookworm-slim` is the default base image; mixing in Ubuntu, CentOS, or other distros is encouraged to make the decoy network look heterogeneous.
- **Networking**: Deckies need to appear as real machines on the LAN (own MACs/IPs). MACVLAN and IPVLAN are candidates; the right driver depends on the host environment. WSL has known limitations — bare metal or a VM is preferred for testing.
- **Log pipeline**: Logstash → ELK stack → SIEM (isolated network, not reachable from decoy network)

## Architecture Constraints

- The decoy network must be reachable from the outside (attacker-facing).
- The logging/aggregation network must be isolated from the decoy network.
- A publicly accessible real server acts as the bridge between the two networks.
- Deckies should differ in exposed services and OS fingerprints to appear as a heterogeneous network.
- **IMPORTANT**: The system now strictly enforces dependency injection for storage. Do not import `SQLiteRepository` directly in new features; instead, use `get_repository()` from the factory or the FastAPI `get_repo` dependency.

## Development and testing

- For every new feature, pytests must me made.
- Pytest is the main testing framework in use.
- NEVER pass broken code to the user.
    - Broken means: not running, not passing 100% tests, etc.
- After tests pass with 100%, always git commit your changes.
- NEVER add "Co-Authored-By" or any Claude attribution lines to git commit messages.
