# DECNET (Deception Network) Project Context

DECNET is a high-fidelity honeypot framework designed to deploy heterogeneous fleets of fake machines (called **deckies**) that appear as real hosts on a local network.

## Project Overview

- **Core Purpose:** To lure, profile, and log attacker interactions within a controlled, deceptive environment.
- **Key Technology:** Linux-native container networking (MACVLAN/IPvlan) combined with Docker to give each decoy its own MAC address, IP, and realistic TCP/IP stack behavior.
- **Main Components:**
  - **Deckies:** Group of containers sharing a network namespace (one base container + multiple service containers).
  - **Archetypes:** Pre-defined machine profiles (e.g., `windows-workstation`, `linux-server`) that bundle services and OS fingerprints.
  - **Services:** Modular honeypot plugins (SSH, SMB, RDP, etc.) built as `BaseService` subclasses.
  - **OS Fingerprinting:** Sysctl-based TCP/IP stack tuning to spoof OS detection (nmap).
  - **Logging Pipeline:** RFC 5424 syslog forwarding to an isolated SIEM/ELK stack.

## Technical Stack

- **Language:** Python 3.11+
- **CLI Framework:** [Typer](https://typer.tiangolo.com/)
- **Data Validation:** [Pydantic v2](https://docs.pydantic.dev/)
- **Orchestration:** Docker Engine 24+ (via Docker SDK for Python)
- **Networking:** MACVLAN (default) or IPvlan L2 (for WiFi/restricted environments).
- **Testing:** Pytest (100% pass requirement).
- **Formatting/Linting:** Ruff, Bandit (SAST), pip-audit.

## Architecture

```text
Host NIC (eth0)
  └── MACVLAN Bridge
        ├── Decky-01 (192.168.1.10) -> [Base] + [SSH] + [HTTP]
        ├── Decky-02 (192.168.1.11) -> [Base] + [SMB] + [RDP]
        └── ...
```

- **Base Container:** Owns the IP/MAC, sets `sysctls` for OS spoofing, and runs `sleep infinity`.
- **Service Containers:** Use `network_mode: service:<base>` to share the identity and networking of the base container.
- **Isolation:** Decoy traffic is strictly separated from the logging network.

## Key Commands

### Development & Maintenance
- **Install (Dev):** 
    - `rm .venv -rf`
    - `python3 -m venv .venv`
    - `source .venv/bin/activate`
    - `pip install -e .`
- **Run Tests:** `pytest` (Run before any commit)
- **Linting:** `ruff check .`
- **Security Scan:** `bandit -r decnet/`
- **Web Git:** git.resacachile.cl (Gitea)

### CLI Usage
- **List Services:** `decnet services`
- **List Archetypes:** `decnet archetypes`
- **Dry Run (Compose Gen):** `decnet deploy --deckies 3 --randomize-services --dry-run`
- **Deploy (Full):** `sudo .venv/bin/decnet deploy --interface eth0 --deckies 5 --randomize-services`
- **Status:** `decnet status`
- **Teardown:** `sudo .venv/bin/decnet teardown --all`

## Development Conventions

- **Code Style:** 
  - Strict adherence to Ruff/PEP8.
  - **Always use typed variables**. If any non-types variables are found, they must be corrected.
    - The correct way is `x: int = 1`, never `x : int = 1`.
    - If assignment is present, always use a space between the type and the equal sign `x: int = 1`.
  - **Never** use lowercase L (l), uppercase o (O) or uppercase i (i) in single-character names.
  - **Internal vars are to be declared with an underscore** (_internal_variable_name).
  - **Internal to internal vars are to be declared with double underscore** (__internal_variable_name).
  - Always use snake_case for code.
  - Always use PascalCase for classes and generics.
- **Testing:** New features MUST include a `pytest` case. 100% test pass rate is mandatory before merging.
- **Plugin System:**
  - New services go in `decnet/services/<name>.py`.
  - Subclass `decnet.services.base.BaseService`.
  - The registry uses auto-discovery; no manual registration required.
- **Configuration:**
  - Use Pydantic models in `decnet/config.py` for any new settings.
  - INI file parsing is handled in `decnet/ini_loader.py`.
- **State Management:**
  - Runtime state is persisted in `decnet-state.json`.
  - Do not modify this file manually.
- **General Development Guidelines**:
  - **Never** commit broken code.
  - **No matter how small** the changes, they must be committed.
  - **If new features are addedd** new tests must be added, too.
  - **Never present broken code to the user**. Test, validate, then present.
  - **Extensive testing** for every function must be created.
  - **Always develop in the `dev` branch, never in `main`.**
  - **Test in the `testing` branch.**

## Directory Structure

- `decnet/`: Main source code.
  - `services/`: Honeypot service implementations.
  - `logging/`: Syslog formatting and forwarding logic.
  - `correlation/`: (In Progress) Logic for grouping attacker events.
- `templates/`: Dockerfiles and entrypoint scripts for services.
- `tests/`: Pytest suite.
- `pyproject.toml`: Dependency and entry point definitions.
- `CLAUDE.md`: Claude-specific environment guidance.
- `DEVELOPMENT.md`: Roadmap and TODOs.
