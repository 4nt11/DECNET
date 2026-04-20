# DECNET Engine (Orchestrator)

The `decnet/engine` module is the central nervous system of DECNET. It acts as the primary orchestrator, responsible for bridging high-level configuration (user-defined deckies and archetypes) with the underlying infrastructure (Docker containers, MACVLAN/IPvlan networking, and host-level configurations).

## Role in the Ecosystem
While the CLI manages user interaction and the Service Registry manages available honeypots, the **Engine** is what actually manifests these concepts into running containers on the network. It handles:
- **Network Virtualization**: Dynamically setting up MACVLAN or IPvlan L2 interfaces.
- **Container Lifecycle**: Orchestrating `docker compose` for building and running services.
- **State Persistence**: Tracking active deployments to ensure clean teardowns.
- **Unified Logging Injection**: Ensuring all honeypots share the same logging utilities.

---

## Core Components

### `deployer.py`
This is the primary implementation file for the engine logic.

#### `deploy(config: DecnetConfig, ...)`
The entry point for a deployment. It executes the following sequence:
1. **Network Setup**: Identifies the IP range required for the requested deckies and initializes the Docker MACVLAN/IPvlan network.
2. **Host Bridge**: Configures host-level routing (via `setup_host_macvlan` or `setup_host_ipvlan`) so the host can communicate with the decoys.
3. **Logging Synchronization**: Copies the `decnet_logging.py` utility into every service's build context to ensure consistent log formatting.
4. **Compose Generation**: Uses the `decnet.composer` to generate a `decnet-compose.yml` file.
5. **State Management**: Saves the current configuration to `decnet-state.json`.
6. **Orchestrated Build/Up**: Executes `docker compose up --build` with automatic retries for transient Docker daemon failures.

#### `teardown(decky_id: str | None = None)`
Handles the cleanup of DECNET resources.
- **Targeted Teardown**: If a `decky_id` is provided, it stops and removes only those specific containers.
- **Full Teardown**: If no ID is provided, it:
    - Stops and removes all DECNET containers.
    - Tears down host-level virtual interfaces.
    - Removes the Docker MACVLAN/IPvlan network.
    - Clears the internal `decnet-state.json`.

#### `status()`
Provides a real-time snapshot of the deployment.
- Queries the Docker SDK for the current status of all containers associated with the active deployment.
- Displays a `rich` table showing Decky names, IPs, Hostnames, and the health status of individual services.

---

## Internal Logic & Helpers

### Infrastructure Orchestration
The Engine relies heavily on sub-processes to interface with `docker compose`, as it provides a robust abstraction for managing complex container groups (Deckies).

- **`_compose_with_retry`**: Docker operations (especially `pull` and `build`) can fail due to network timeouts or registry issues. This helper implements exponential backoff to ensure high reliability during deployment.
- **`_compose`**: A direct wrapper for `docker compose` commands used during teardown where retries are less critical.

### The Logging Helper (`_sync_logging_helper`)
One of the most critical parts of the engine is ensuring that every honeypot service, regardless of its unique implementation, speaks the same syslog "language." The engine iterates through every active service and copies `templates/decnet_logging.py` into their respective build contexts before the build starts. This allows service containers to import the standardized logging logic at runtime.

---

## Error Handling & Resilience
The Engine is designed to handle "Permanent" vs "Transient" failures. It identifies errors such as `manifest unknown` or `repository does not exist` as terminal and will abort immediately, while others (connection resets, daemon timeouts) trigger a retry cycle.

## State Management
The Engine maintains a `decnet-state.json` file. This file acts as the source of truth for what is currently "on the wire." Without this state, a proper `teardown` would be impossible, as the engine wouldn't know which virtual interfaces were created on the host NIC.
