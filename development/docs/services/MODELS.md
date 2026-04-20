# DECNET Domain Models

> [!IMPORTANT]
> **DEVELOPMENT DISCLAIMER**: DECNET is currently in active development. The models defined in `decnet/models.py` are subject to significant changes as the framework evolves.

## Overview

The `decnet/models.py` file serves as the centralized repository for all **Domain Models** used throughout the project. These are implemented using Pydantic v2 and ensure that the core business logic remains decoupled from the specific implementation details of the database (SQLAlchemy/SQLite) or the web layer (FastAPI).

---

## Model Hierarchy

DECNET categorizes its models into two primary functional groups: **INI Specifications** and **Runtime Configurations**.

### 1. INI Specifications (Input Validation)
These models are designed to represent the structure of a `decnet.ini` file. They are primarily consumed by the `ini_loader.py` during the parsing of user-provided configuration files.

- **`IniConfig`**: The root model for a full deployment specification. It includes global settings like `subnet`, `gateway`, and `interface`, and contains a list of `DeckySpec` objects.
- **`DeckySpec`**: A high-level description of a machine. It contains optional fields that the user *may* provide in an INI file (e.g., `ip`, `archetype`, `services`).
- **`CustomServiceSpec`**: Defines external "Bring-Your-Own" services using Docker images and custom execution commands.

### 2. Runtime Configurations (Operational State)
These models represent the **active, fully resolved state** of the deployment. Unlike the specifications, these models require all fields to be populated and valid.

- **`DecnetConfig`**: The operational root of a deployment. It includes the resolved network settings and the list of active `DeckyConfig` objects. It is used by the **Engine** for orchestration and is persisted in `decnet-state.json`.
- **`DeckyConfig`**: A fully materialized decoy configuration. It includes generated hostnames, resolved distro images, and specific IP addresses.

---

## The Fleet Transformer (`fleet.py`)

The connection between the **Specifications** and the **Runtime Configurations** is handled by `decnet/fleet.py`.

The function `build_deckies_from_ini` takes an `IniConfig` as input and performs the following "up-conversion" logic:
- **IP Allocation**: Auto-allocates free IPs from the subnet for any deckies missing an explicit IP in the INI.
- **Service Resolution**: Validates that all requested services exist in the registry and assigns defaults from archetypes if needed.
- **Environment Inheritance**: Inherits settings like rotation intervals (`mutate_interval`) from the global INI context down to individual deckies.

---

## Structural Validation: `IniContent`

To ensure that saved deployments in the database or provided by the API remain structurally sound, DECNET uses a specialized `IniContent` type.

- **`validate_ini_string`**: A pre-validator that uses Python's native `configparser`. It ensures that the content is a valid INI string, does not exceed 512KB, and contains at least one section.
- **Standardized Errors**: It raises specifically formatted `ValueError` exceptions that are captured by both the CLI and the Web UI to provide clear feedback to the user.

---

## Key Consumer Modules

| Module | Usage |
| :--- | :--- |
| **`decnet/ini_loader.py`** | Uses `IniConfig` and `DeckySpec` to parse raw `.ini` files into structured objects. |
| **`decnet/fleet.py`** | Transforms `IniConfig` specs into `DeckyConfig` operational models. |
| **`decnet/config.py`** | Uses `DecnetConfig` and `DeckyConfig` to manage the lifecycle of `decnet-state.json`. |
| **`decnet/web/db/models.py`** | Utilizes `IniContent` to enforce structural validity on INI strings stored in the database. |
