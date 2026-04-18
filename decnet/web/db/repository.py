from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseRepository(ABC):
    """Abstract base class for DECNET web dashboard data storage."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the database schema."""
        pass

    @abstractmethod
    async def add_log(self, log_data: dict[str, Any]) -> None:
        """Add a new log entry to the database."""
        pass

    async def add_logs(self, log_entries: list[dict[str, Any]]) -> None:
        """Bulk-insert log entries in a single transaction.

        Default implementation falls back to per-row add_log; concrete
        repositories should override for a real single-commit insert.
        """
        for _entry in log_entries:
            await self.add_log(_entry)

    @abstractmethod
    async def get_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Retrieve paginated log entries."""
        pass

    @abstractmethod
    async def get_total_logs(self, search: Optional[str] = None) -> int:
        """Retrieve the total count of logs, optionally filtered by search."""
        pass

    @abstractmethod
    async def get_stats_summary(self) -> dict[str, Any]:
        """Retrieve high-level dashboard metrics."""
        pass

    @abstractmethod
    async def get_deckies(self) -> list[dict[str, Any]]:
        """Retrieve the list of currently deployed deckies."""
        pass

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        """Retrieve a user by their username."""
        pass

    @abstractmethod
    async def get_user_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        """Retrieve a user by their UUID."""
        pass

    @abstractmethod
    async def create_user(self, user_data: dict[str, Any]) -> None:
        """Create a new dashboard user."""
        pass

    @abstractmethod
    async def update_user_password(self, uuid: str, password_hash: str, must_change_password: bool = False) -> None:
        """Update a user's password and change the must_change_password flag."""
        pass

    @abstractmethod
    async def list_users(self) -> list[dict[str, Any]]:
        """Retrieve all users (caller must strip password_hash before returning to clients)."""
        pass

    @abstractmethod
    async def delete_user(self, uuid: str) -> bool:
        """Delete a user by UUID. Returns True if user was found and deleted."""
        pass

    @abstractmethod
    async def update_user_role(self, uuid: str, role: str) -> None:
        """Update a user's role."""
        pass

    @abstractmethod
    async def purge_logs_and_bounties(self) -> dict[str, int]:
        """Delete all logs, bounties, and attacker profiles. Returns counts of deleted rows."""
        pass

    @abstractmethod
    async def add_bounty(self, bounty_data: dict[str, Any]) -> None:
        """Add a new harvested artifact (bounty) to the database."""
        pass

    @abstractmethod
    async def get_bounties(
        self,
        limit: int = 50,
        offset: int = 0,
        bounty_type: Optional[str] = None,
        search: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Retrieve paginated bounty entries."""
        pass

    @abstractmethod
    async def get_total_bounties(self, bounty_type: Optional[str] = None, search: Optional[str] = None) -> int:
        """Retrieve the total count of bounties, optionally filtered."""
        pass

    @abstractmethod
    async def get_state(self, key: str) -> Optional[dict[str, Any]]:
        """Retrieve a specific state entry by key."""
        pass

    @abstractmethod
    async def set_state(self, key: str, value: Any) -> None:
        """Store a specific state entry by key."""
        pass

    @abstractmethod
    async def get_max_log_id(self) -> int:
        """Return the highest log ID, or 0 if the table is empty."""
        pass

    @abstractmethod
    async def get_logs_after_id(self, last_id: int, limit: int = 500) -> list[dict[str, Any]]:
        """Return logs with id > last_id, ordered by id ASC, up to limit."""
        pass

    @abstractmethod
    async def get_all_bounties_by_ip(self) -> dict[str, list[dict[str, Any]]]:
        """Retrieve all bounty rows grouped by attacker_ip."""
        pass

    @abstractmethod
    async def get_bounties_for_ips(self, ips: set[str]) -> dict[str, list[dict[str, Any]]]:
        """Retrieve bounty rows grouped by attacker_ip, filtered to only the given IPs."""
        pass

    @abstractmethod
    async def upsert_attacker(self, data: dict[str, Any]) -> str:
        """Insert or replace an attacker profile record. Returns the row's UUID."""
        pass

    @abstractmethod
    async def upsert_attacker_behavior(self, attacker_uuid: str, data: dict[str, Any]) -> None:
        """Insert or replace the behavioral/fingerprint row for an attacker."""
        pass

    @abstractmethod
    async def get_attacker_behavior(self, attacker_uuid: str) -> Optional[dict[str, Any]]:
        """Retrieve the behavioral/fingerprint row for an attacker UUID."""
        pass

    @abstractmethod
    async def get_behaviors_for_ips(self, ips: set[str]) -> dict[str, dict[str, Any]]:
        """Bulk-fetch behavior rows keyed by attacker IP (JOIN to attackers)."""
        pass

    @abstractmethod
    async def get_attacker_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        """Retrieve a single attacker profile by UUID."""
        pass

    @abstractmethod
    async def get_attackers(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        sort_by: str = "recent",
        service: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Retrieve paginated attacker profile records."""
        pass

    @abstractmethod
    async def get_total_attackers(self, search: Optional[str] = None, service: Optional[str] = None) -> int:
        """Retrieve the total count of attacker profile records, optionally filtered."""
        pass

    @abstractmethod
    async def get_attacker_commands(
        self,
        uuid: str,
        limit: int = 50,
        offset: int = 0,
        service: Optional[str] = None,
    ) -> dict[str, Any]:
        """Retrieve paginated commands for an attacker, optionally filtered by service."""
        pass

    @abstractmethod
    async def get_attacker_artifacts(self, uuid: str) -> list[dict[str, Any]]:
        """Return `file_captured` log rows for this attacker, newest first."""
        pass
