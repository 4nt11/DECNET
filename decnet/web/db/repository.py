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
    async def upsert_session_profile(self, sid: str, data: dict[str, Any]) -> None:
        """Insert or update the keystroke-dynamics profile row for a session."""
        pass

    @abstractmethod
    async def get_session_profile(self, sid: str) -> Optional[dict[str, Any]]:
        """Retrieve the keystroke-dynamics profile row for a session."""
        pass

    @abstractmethod
    async def increment_smtp_target(self, attacker_uuid: str, domain: str) -> None:
        """
        Record that ``attacker_uuid`` targeted ``domain`` via SMTP.

        Upserts the (attacker_uuid, domain) row: inserts with count=1 +
        first_seen=now on first sight, bumps count + last_seen on every
        subsequent hit. Callers must pre-normalize ``domain`` (lowercase,
        local-part stripped).
        """
        pass

    @abstractmethod
    async def list_smtp_targets(self, attacker_uuid: str) -> list[dict[str, Any]]:
        """Return SmtpTarget rows for an attacker, ordered by most-recent first."""
        pass

    @abstractmethod
    async def get_attacker_stored_mail(self, uuid: str) -> list[Any]:
        """Return `message_stored` log rows for an attacker, newest first."""
        pass

    @abstractmethod
    async def smtp_target_seen(self, domain: str) -> dict[str, Any]:
        """
        Cross-attacker aggregate for a victim domain.

        Returns ``{seen: bool, count: int, first_seen: datetime|None,
        last_seen: datetime|None}``. Shaped as the federation-gossip RPC
        that V2 will expose — each operator can answer "have any of your
        attackers targeted this domain?" without leaking attacker identity.
        """
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

    @abstractmethod
    async def get_attacker_transcripts(self, uuid: str) -> list[dict[str, Any]]:
        """Return `session_recorded` log rows for this attacker, newest first."""
        pass

    async def get_attacker_service_activity(
        self, attacker_uuid: str
    ) -> list[tuple[str, str]]:
        """Return the distinct ``(service, event_type)`` pairs observed
        for one attacker, for bucketing into scanned vs. interacted
        services.  Default is NotImplementedError so non-SQLModel backends
        must opt in; SQLModelRepository overrides with a cheap DISTINCT
        query."""
        raise NotImplementedError

    @abstractmethod
    async def get_session_log(self, sid: str) -> Optional[dict[str, Any]]:
        """Look up the `session_recorded` Log row for a given session UUID."""
        pass

    # ------------------------------------------------------------- swarm
    # Swarm methods have default no-op / empty implementations so existing
    # subclasses and non-swarm deployments continue to work without change.

    async def add_swarm_host(self, data: dict[str, Any]) -> None:
        raise NotImplementedError

    async def get_swarm_host_by_name(self, name: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def get_swarm_host_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def get_swarm_host_by_fingerprint(self, fingerprint: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def list_swarm_hosts(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def update_swarm_host(self, uuid: str, fields: dict[str, Any]) -> None:
        raise NotImplementedError

    async def delete_swarm_host(self, uuid: str) -> bool:
        raise NotImplementedError

    async def upsert_decky_shard(self, data: dict[str, Any]) -> None:
        raise NotImplementedError

    async def list_decky_shards(self, host_uuid: Optional[str] = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def delete_decky_shards_for_host(self, host_uuid: str) -> int:
        raise NotImplementedError

    async def delete_decky_shard(self, decky_name: str) -> bool:
        raise NotImplementedError

    # ----------------------------------------------------------- mazenet
    # MazeNET topology persistence.  Default no-op / NotImplementedError so
    # non-default backends stay functional; SQLModelRepository provides the
    # real implementation used by SQLite and MySQL.

    async def create_topology(self, data: dict[str, Any]) -> str:
        raise NotImplementedError

    async def get_topology(self, topology_id: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def list_topologies(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def count_topologies(self, status: Optional[str] = None) -> int:
        raise NotImplementedError

    async def update_topology_status(
        self,
        topology_id: str,
        new_status: str,
        reason: Optional[str] = None,
    ) -> None:
        raise NotImplementedError

    async def delete_topology_cascade(self, topology_id: str) -> bool:
        raise NotImplementedError

    async def set_topology_resync(self, topology_id: str, value: bool) -> None:
        raise NotImplementedError

    async def list_topologies_needing_resync(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def add_lan(self, data: dict[str, Any]) -> str:
        raise NotImplementedError

    async def update_lan(
        self,
        lan_id: str,
        fields: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = False,
    ) -> None:
        raise NotImplementedError

    async def list_lans_for_topology(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def add_topology_decky(self, data: dict[str, Any]) -> str:
        raise NotImplementedError

    async def update_topology_decky(
        self,
        decky_uuid: str,
        fields: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
        enforce_pending: bool = False,
    ) -> None:
        raise NotImplementedError

    async def list_topology_deckies(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def add_topology_edge(self, data: dict[str, Any]) -> str:
        raise NotImplementedError

    async def list_topology_edges(
        self, topology_id: str
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def list_topology_status_events(
        self, topology_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    # -------------------- pre-deploy (pending-only) mutations --------------------

    async def delete_lan(
        self, lan_id: str, *, expected_version: Optional[int] = None
    ) -> None:
        raise NotImplementedError

    async def delete_topology_decky(
        self, decky_uuid: str, *, expected_version: Optional[int] = None
    ) -> None:
        raise NotImplementedError

    async def delete_topology_edge(
        self, edge_id: str, *, expected_version: Optional[int] = None
    ) -> None:
        raise NotImplementedError

    # -------------------- live mutation queue (reconciler) --------------------

    async def enqueue_topology_mutation(
        self,
        topology_id: str,
        op: str,
        payload: dict[str, Any],
        *,
        expected_version: Optional[int] = None,
    ) -> str:
        raise NotImplementedError

    async def claim_next_mutation(
        self, topology_id: str
    ) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def mark_mutation_applied(self, mutation_id: str) -> None:
        raise NotImplementedError

    async def mark_mutation_failed(
        self, mutation_id: str, reason: str
    ) -> None:
        raise NotImplementedError

    async def list_topology_mutations(
        self,
        topology_id: str,
        state: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def has_pending_topology_mutation(self) -> bool:
        return False

    async def list_live_topology_ids(self) -> list[str]:
        return []

    # --------------------------------------------------------- webhooks
    # Webhook subscriptions — external SIEM / SOAR egress configuration.
    # Default NotImplementedError keeps non-default backends honest; the
    # SQLModel-backed SQLite and MySQL repos override everything below.

    async def create_webhook_subscription(self, data: dict[str, Any]) -> None:
        raise NotImplementedError

    async def get_webhook_subscription(self, uuid: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def get_webhook_subscription_by_name(
        self, name: str
    ) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def list_webhook_subscriptions(
        self, enabled_only: bool = False
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def update_webhook_subscription(
        self, uuid: str, patch: dict[str, Any]
    ) -> bool:
        raise NotImplementedError

    async def delete_webhook_subscription(self, uuid: str) -> bool:
        raise NotImplementedError

    async def record_webhook_success(self, uuid: str, ts: Any) -> None:
        raise NotImplementedError

    async def record_webhook_failure(
        self, uuid: str, ts: Any, error: str
    ) -> int:
        """Record a failed delivery; return the new ``consecutive_failures``
        count so the caller can decide whether to trip the circuit."""
        raise NotImplementedError

    async def trip_webhook_circuit(self, uuid: str, ts: Any) -> None:
        """Auto-disable a subscription after repeated failures. Sets
        ``enabled=False`` and stamps ``auto_disabled_at``."""
        raise NotImplementedError
