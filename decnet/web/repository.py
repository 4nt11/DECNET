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
    async def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        """Retrieve a user by their username."""
        pass

    @abstractmethod
    async def create_user(self, user_data: dict[str, Any]) -> None:
        """Create a new dashboard user."""
        pass
