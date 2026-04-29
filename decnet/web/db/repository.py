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

    # ---- credentials ---------------------------------------------------

    @abstractmethod
    async def upsert_credential(self, data: dict[str, Any]) -> int:
        """Insert or upsert a credential attempt; returns the row id.

        Dedup tuple: (attacker_ip, decky_name, service, secret_sha256,
        principal_or_None). On dedup match, ``attempt_count`` is bumped
        and ``last_seen`` updated; the originally-seen ``first_seen``
        and ``fields`` JSON are preserved.
        """
        pass

    @abstractmethod
    async def get_credentials(
        self,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        service: Optional[str] = None,
        attacker_ip: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Paginated credential rows, with optional filters."""
        pass

    @abstractmethod
    async def get_total_credentials(
        self,
        search: Optional[str] = None,
        service: Optional[str] = None,
        attacker_ip: Optional[str] = None,
    ) -> int:
        """Total credential count under the same filters as get_credentials."""
        pass

    @abstractmethod
    async def get_credentials_for_attacker(
        self, attacker_ip: str
    ) -> list[dict[str, Any]]:
        """Every credential row from the given attacker IP."""
        pass

    @abstractmethod
    async def get_credential_attempts_for_secret(
        self, secret_sha256: str
    ) -> list[dict[str, Any]]:
        """Every (attacker, decky, service, principal) row sharing this secret hash."""
        pass

    @abstractmethod
    async def upsert_credential_reuse(
        self,
        *,
        secret_sha256: str,
        secret_kind: str,
        principal: Optional[str],
        attacker_uuid: Optional[str],
        attacker_ip: str,
        decky: str,
        service: str,
        attempt_count: int,
        ts: Optional[Any] = None,
    ) -> Optional[dict[str, Any]]:
        """Upsert one credential-reuse finding. Returns the row dict (with
        ``inserted: bool`` mixed in) on insert/update, or None if the row
        is below the reuse threshold and shouldn't be persisted yet.
        """
        pass

    @abstractmethod
    async def find_credential_reuse_candidates(
        self, min_targets: int = 2
    ) -> list[dict[str, Any]]:
        """Group ``credentials`` by ``(secret_sha256, secret_kind, principal)``
        and return groups whose distinct ``(decky_name, service)`` count is
        at least *min_targets*. Each entry has the group key, the
        ``target_count``, and the underlying credential rows for the
        correlator to fold into ``CredentialReuse``.
        """
        pass

    @abstractmethod
    async def list_credential_reuses(
        self,
        limit: int = 50,
        offset: int = 0,
        min_target_count: int = 2,
        secret_kind: Optional[str] = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Paged list of credential-reuse findings ordered by target_count desc."""
        pass

    @abstractmethod
    async def get_credential_reuse_by_id(
        self, reuse_id: str
    ) -> Optional[dict[str, Any]]:
        """One credential-reuse finding by UUID, or None."""
        pass

    @abstractmethod
    async def update_credential_attacker_uuid(
        self, attacker_ip: str, attacker_uuid: str
    ) -> int:
        """Backfill ``attacker_uuid`` on every Credential row matching the IP
        whose ``attacker_uuid`` is currently null. Returns rows updated.
        """
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
    async def upsert_attacker_intel(self, data: dict[str, Any]) -> str:
        """Insert or update the threat-intel row for an attacker UUID.

        ``data`` MUST include ``attacker_uuid``, ``attacker_ip`` and
        ``expires_at``. Returns the row UUID. Keyed on ``attacker_uuid``
        (UNIQUE + FK to ``attackers.uuid``); ``attacker_ip`` is denormalised
        — it gets overwritten on every upsert if the attacker rotates IPs.
        """
        pass

    @abstractmethod
    async def get_attacker_intel_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        """Return the threat-intel row for ``uuid`` or ``None`` if missing."""
        pass

    @abstractmethod
    async def get_unenriched_attackers(
        self, limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List ``{"uuid", "ip"}`` pairs for attackers with no intel row OR
        whose row is past ``expires_at``.

        Used by the enrich worker to backfill on startup and on each wake.
        Returns both fields so the worker can write keyed on UUID without
        a second per-attacker DB round-trip to resolve the IP for outbound
        provider calls.
        """
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

    # ─── Identity resolution (Observation → Identity → Campaign) ───────────
    # The clusterer that populates these rows is a separate downstream
    # effort. The read-only API ships first; until the clusterer runs,
    # every method below returns empty/None against an empty table.
    # See development/IDENTITY_RESOLUTION.md.

    @abstractmethod
    async def get_identity_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        """
        Return one ``AttackerIdentity`` row by UUID, or ``None`` if absent.

        If the row has ``merged_into_uuid`` set (i.e. the clusterer
        soft-merged it into another identity), implementations MUST
        follow the chain and return the winner — callers should never
        see a merged-out row as the answer to a fresh query.
        """
        pass

    @abstractmethod
    async def list_identities(
        self, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Paginated list of identity rows, newest-updated first."""
        pass

    @abstractmethod
    async def count_identities(self) -> int:
        """Total identity rows. Excludes merged-out rows."""
        pass

    @abstractmethod
    async def list_observations_for_identity(
        self, identity_uuid: str, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        """``Attacker`` observation rows linked to the given identity, newest first."""
        pass

    @abstractmethod
    async def count_observations_for_identity(self, identity_uuid: str) -> int:
        """Total ``Attacker`` rows FK'd to this identity."""
        pass

    # ─── Identity resolution writes (clusterer worker) ─────────────────────
    # Populated by ``decnet clusterer``. The read-only API on top of
    # ``attacker_identities`` shipped in commit ``dc3d08d``; this is the
    # write side. See ``decnet.clustering.impl.connected_components``.

    @abstractmethod
    async def list_attackers_for_clustering(
        self, limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Project every ``Attacker`` into the clusterer's input shape.

        Returns dicts with at least ``uuid``, ``asn``, ``identity_id``,
        and ``fingerprints`` (raw JSON list). The clusterer parses the
        fingerprints list to recover JA3 / HASSH per observation. Empty
        list when no attackers exist.

        ``limit`` is optional — passed by callers that want to bound a
        single tick's working set; leave ``None`` to fetch all.
        """
        pass

    @abstractmethod
    async def create_attacker_identity(self, row: dict[str, Any]) -> str:
        """Insert a new ``AttackerIdentity`` row and return its uuid.

        ``row`` must include ``uuid``; other fields are optional and
        default per the model. Caller is responsible for generating
        the uuid (so it can be used in the same tick to back-link
        observations without a second round-trip).
        """
        pass

    @abstractmethod
    async def set_attacker_identity_id(
        self, attacker_uuid: str, identity_uuid: str,
    ) -> None:
        """Set ``attackers.identity_id`` on a single observation row.

        Idempotent — re-setting the same value is a no-op. Used by
        the clusterer when it links an observation to an identity.
        """
        pass

    @abstractmethod
    async def list_all_identities(self) -> list[dict[str, Any]]:
        """Every ``AttackerIdentity`` row, including merged-out ones.

        Distinct from :meth:`list_identities`, which filters out
        merged-out rows for the de-duped UI list. The clusterer's
        revocable-merge pass needs to re-evaluate merged-out
        identities, so it pulls the unfiltered set.
        """
        pass

    @abstractmethod
    async def update_identity_merged_into(
        self, identity_uuid: str, winner_uuid: Optional[str],
    ) -> None:
        """Set or clear ``attacker_identities.merged_into_uuid``.

        Pass ``winner_uuid`` to soft-merge the row into another
        identity; pass ``None`` to revoke a prior merge (the
        revocable-merge undo path). Observations stay FK'd to their
        original identity row throughout — the merge is a soft
        pointer, not a re-point.
        """
        pass

    @abstractmethod
    async def update_identity_fingerprints(
        self,
        identity_uuid: str,
        *,
        ja3_hashes: Optional[str] = None,
        hassh_hashes: Optional[str] = None,
        tls_cert_sha256: Optional[str] = None,
    ) -> None:
        """Set the fingerprint summary columns on one ``AttackerIdentity``.

        Each argument is a JSON-encoded ``list[str]`` (the federation
        wire shape) or ``None`` to leave the corresponding column at
        ``NULL``. Always overwrites — the rollup writer is the source
        of truth for these columns, computed deterministically from
        the identity's member observations every clusterer tick. Also
        bumps ``updated_at`` so cache subscribers can invalidate.
        """
        pass

    # ─── Campaign clustering reads ────────────────────────────────────────
    # Layer above identity resolution: campaigns group identities into
    # operations. Populated by ``decnet campaign-clusterer``. The
    # read-only API below ships in the same wave; until the clusterer
    # runs, every method returns empty/None against an empty table.
    # See development/CAMPAIGN_CLUSTERING.md.

    @abstractmethod
    async def get_campaign_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        """
        Return one ``Campaign`` row by UUID, or ``None`` if absent.

        If the row has ``merged_into_uuid`` set (i.e. the clusterer
        soft-merged it into another campaign), implementations MUST
        follow the chain and return the winner — same contract as
        :meth:`get_identity_by_uuid`.
        """
        pass

    @abstractmethod
    async def list_campaigns(
        self, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Paginated list of campaign rows, newest-updated first.

        Excludes merged-out rows so the list view is the de-duped truth
        (mirrors :meth:`list_identities`).
        """
        pass

    @abstractmethod
    async def count_campaigns(self) -> int:
        """Total campaign rows. Excludes merged-out rows."""
        pass

    @abstractmethod
    async def list_identities_for_campaign(
        self, campaign_uuid: str, limit: int = 50, offset: int = 0,
    ) -> list[dict[str, Any]]:
        """``AttackerIdentity`` rows linked to the given campaign, newest first."""
        pass

    @abstractmethod
    async def count_identities_for_campaign(self, campaign_uuid: str) -> int:
        """Total ``AttackerIdentity`` rows FK'd to this campaign."""
        pass

    # ─── Campaign clustering writes (campaign-clusterer worker) ───────────

    @abstractmethod
    async def list_identities_for_clustering(
        self, limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Project every ``AttackerIdentity`` into the campaign
        clusterer's input shape.

        Returns dicts with at least ``uuid``, ``campaign_id``,
        aggregated fingerprint summaries (``ja3_hashes``,
        ``hassh_hashes``, ``payload_simhashes``, ``c2_endpoints``),
        ``first_seen_at`` / ``last_seen_at``, ``merged_into_uuid``.
        Empty list when no identities exist. ``limit`` bounds a
        single tick's working set; leave ``None`` to fetch all.
        """
        pass

    @abstractmethod
    async def create_campaign(self, row: dict[str, Any]) -> str:
        """Insert a new ``Campaign`` row and return its uuid.

        ``row`` must include ``uuid``; other fields are optional and
        default per the model. Caller generates the uuid so it can be
        used in the same tick to back-link identities.
        """
        pass

    @abstractmethod
    async def set_identity_campaign_id(
        self, identity_uuid: str, campaign_uuid: Optional[str],
    ) -> None:
        """Set or clear ``attacker_identities.campaign_id``.

        Idempotent. Pass ``None`` to unlink (e.g. when revoking a
        prior campaign assignment).
        """
        pass

    @abstractmethod
    async def list_all_campaigns(self) -> list[dict[str, Any]]:
        """Every ``Campaign`` row, including merged-out ones.

        Distinct from :meth:`list_campaigns`: the clusterer's
        revocable-merge pass needs to re-evaluate merged-out
        campaigns, so it pulls the unfiltered set.
        """
        pass

    @abstractmethod
    async def update_campaign_merged_into(
        self, campaign_uuid: str, winner_uuid: Optional[str],
    ) -> None:
        """Set or clear ``campaigns.merged_into_uuid``.

        Pass ``winner_uuid`` to soft-merge the row into another
        campaign; pass ``None`` to revoke a prior merge.
        """
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

    async def get_attacker_ip_leaks(
        self, attacker_uuid: str, *, limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return up to ``limit`` ``bounty_type='ip_leak'`` rows for the
        attacker, newest first. Each row's payload carries the TCP
        source IP, the header that leaked, and the claimed real IP —
        see the XFF-mismatch extractor in ``decnet.web.ingester`` for
        the shape. Caller pairs with :meth:`count_attacker_ip_leaks`
        to detect XFF-rotation (100+ claimed IPs from one source)."""
        raise NotImplementedError

    async def count_attacker_ip_leaks(self, attacker_uuid: str) -> int:
        """Total number of ``ip_leak`` bounties recorded for this
        attacker. Used to detect XFF-rotation signal where the attacker
        cycles through many claimed IPs (WAF-bypass-list probing)."""
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

    async def set_topology_email_personas(
        self, topology_id: str, personas_json: str,
    ) -> bool:
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

    # ------------------------------------------------------------ canary
    # Canary-token CRUD.  Same NotImplementedError default as webhooks.
    # Three resources: blobs (operator uploads, deduped), tokens (one
    # planted artifact in one decky), triggers (append-only callback log).

    async def upsert_canary_blob(self, data: dict[str, Any]) -> dict[str, Any]:
        """Insert a CanaryBlob, or return the existing row matching
        ``sha256``.  Returns the row dict either way so the caller can
        report ``token_count`` and ``uploaded_at`` of the canonical row.
        """
        raise NotImplementedError

    async def get_canary_blob(self, uuid: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def get_canary_blob_by_sha256(
        self, sha256: str
    ) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def list_canary_blobs(self) -> list[dict[str, Any]]:
        """Each row carries ``token_count`` (live references) so the UI
        can grey out blobs that are still in use and the delete path
        can return 409 without a second query.
        """
        raise NotImplementedError

    async def delete_canary_blob(self, uuid: str) -> bool:
        """Refcount-aware: returns False if any token still references
        the blob; raises nothing for the not-found case (also False).
        """
        raise NotImplementedError

    async def create_canary_token(self, data: dict[str, Any]) -> None:
        raise NotImplementedError

    async def get_canary_token(self, uuid: str) -> Optional[dict[str, Any]]:
        raise NotImplementedError

    async def get_canary_token_by_slug(
        self, callback_token: str
    ) -> Optional[dict[str, Any]]:
        """Hot path for ``decnet canary`` — slug lookup on every HTTP
        hit and DNS query.  Indexed unique on the column.
        """
        raise NotImplementedError

    async def list_canary_tokens(
        self,
        *,
        decky_name: Optional[str] = None,
        state: Optional[str] = None,
        kind: Optional[str] = None,
        topology_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def update_canary_token_state(
        self,
        uuid: str,
        state: str,
        last_error: Optional[str] = None,
    ) -> bool:
        """Used by the planter when placement succeeds/fails and by the
        revoke path."""
        raise NotImplementedError

    async def record_canary_trigger(
        self, data: dict[str, Any]
    ) -> str:
        """Insert a trigger row and bump the parent token's
        ``trigger_count`` + ``last_triggered_at``.  Returns the new
        trigger uuid so the caller can reference it in the bus event.
        """
        raise NotImplementedError

    async def list_canary_triggers(
        self, token_uuid: str, *, limit: int = 100, offset: int = 0,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def attribute_canary_trigger(
        self, trigger_uuid: str, attacker_id: str,
    ) -> bool:
        """Set ``attacker_id`` on a trigger row.  Called by the
        correlator after it links ``src_ip`` to an existing
        :class:`Attacker` (idempotent).
        """
        raise NotImplementedError

    # ----------------------------------------------------------------- fleet

    async def upsert_fleet_decky(self, data: dict[str, Any]) -> None:
        """Insert-or-update a FleetDecky row keyed by ``(host_uuid, name)``.

        Used by ``engine.deployer.deploy`` and the API deploy path to mirror
        ``decnet-state.json`` into the DB.  Idempotent: calling with the same
        key updates the existing row's mutable fields.
        """
        raise NotImplementedError

    async def delete_fleet_decky(self, *, host_uuid: str, name: str) -> None:
        """Remove a FleetDecky row.  No-op if the row doesn't exist."""
        raise NotImplementedError

    async def list_fleet_deckies(
        self, *, host_uuid: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return all FleetDecky rows, optionally scoped to a single host."""
        raise NotImplementedError

    async def list_running_fleet_deckies(self) -> list[dict[str, Any]]:
        """Return every FleetDecky row whose ``state == 'running'``.

        Joined alongside :meth:`list_running_topology_deckies` and the SWARM
        ``DeckyShard`` view by :meth:`list_running_deckies`.
        """
        raise NotImplementedError

    async def update_fleet_decky_state(
        self, *, host_uuid: str, name: str, state: str,
        last_error: Optional[str] = None,
    ) -> None:
        """Update only the ``state``/``last_error``/``last_seen`` fields.

        Called by the reconciler when ``docker inspect`` reports a fresh
        container state.  Avoids clobbering operator-edited config fields.
        """
        raise NotImplementedError

    async def list_running_deckies(self) -> list[dict[str, Any]]:
        """Union of running deckies across MazeNET, SWARM, and fleet sources.

        Returns dicts shaped for the orchestrator's scheduler:
        ``{uuid, name, ip, services: list[str], source}`` where ``source`` is
        one of ``"topology" | "shard" | "fleet"``.  Rows from each source are
        normalised so the scheduler doesn't need to branch on origin.
        """
        raise NotImplementedError

    # ---------------------------------------------------------- orchestrator

    async def list_running_topology_deckies(self) -> list[dict[str, Any]]:
        """Return every TopologyDecky row whose ``state == 'running'``.

        The orchestrator picks pairs from this set to drive synthetic
        inter-decky activity. Cross-topology by design: a multi-topology
        host still has a single orchestrator instance.
        """
        raise NotImplementedError

    async def record_orchestrator_event(self, data: dict[str, Any]) -> str:
        """Insert one orchestrator-emitted event row, returning its uuid."""
        raise NotImplementedError

    async def list_orchestrator_events(
        self,
        limit: int = 100,
        offset: int = 0,
        *,
        kind: Optional[str] = None,
        since_ts: Optional[Any] = None,
    ) -> list[dict[str, Any]]:
        """Paginated orchestrator events newest-first.

        ``kind`` filters to ``"traffic"`` | ``"file"`` (matches
        :class:`OrchestratorEvent.kind`). ``since_ts`` is the snapshot
        delta filter used by SSE replay; leave ``None`` for the list view.
        """
        raise NotImplementedError

    async def count_orchestrator_events(
        self, *, kind: Optional[str] = None,
    ) -> int:
        """Total orchestrator-event rows, optionally filtered by kind."""
        raise NotImplementedError

    async def prune_orchestrator_events(self, per_dst_cap: int = 10000) -> int:
        """Trim per-``dst_decky_uuid`` rows to a cap. Returns deleted count.

        Periodic prune target — keeps the orchestrator_events table from
        unbounded growth without paying the cost on every write.
        """
        raise NotImplementedError

    async def record_orchestrator_email(self, data: dict[str, Any]) -> str:
        """Insert one orchestrator-generated email row, returning its uuid."""
        raise NotImplementedError

    async def list_orchestrator_emails(
        self,
        limit: int = 100,
        offset: int = 0,
        *,
        mail_decky_uuid: Optional[str] = None,
        thread_id: Optional[str] = None,
        since_ts: Optional[Any] = None,
    ) -> list[dict[str, Any]]:
        """Paginated orchestrator emails newest-first.

        Optional filters narrow to a single mail decky or to one thread,
        used by the dashboard's mailbox-inspector view.
        """
        raise NotImplementedError

    async def count_orchestrator_emails(
        self,
        *,
        mail_decky_uuid: Optional[str] = None,
    ) -> int:
        """Total orchestrator-email rows, optionally filtered by mail decky."""
        raise NotImplementedError

    async def list_orchestrator_email_threads(
        self,
        mail_decky_uuid: str,
        sender_email: str,
        recipient_email: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Open threads between *sender_email* and *recipient_email* on
        *mail_decky_uuid*, newest-first.

        Used by the emailgen scheduler to decide whether to start a new
        thread or reply on an existing one.  Each entry is one row's
        worth of dict — the worker only needs ``thread_id`` and the most
        recent ``message_id`` / ``subject`` to build the reply.
        """
        raise NotImplementedError

    async def prune_orchestrator_emails(self, per_decky_cap: int = 10000) -> int:
        """Trim per-``mail_decky_uuid`` rows to a cap. Returns deleted count.

        Mirrors :meth:`prune_orchestrator_events`; emailgen worker calls
        this on a periodic tick.
        """
        raise NotImplementedError

    # ------------------------------------------------------------- realism

    async def record_synthetic_file(self, data: dict[str, Any]) -> str:
        """Insert a new synthetic_files row, returning its uuid.

        The ``(decky_uuid, path)`` pair has a UNIQUE constraint, so two
        creates for the same target raise — callers either use this for
        first-time plants and :meth:`update_synthetic_file` for edits,
        or wrap in a transaction that catches the conflict.
        """
        raise NotImplementedError

    async def update_synthetic_file(
        self, uuid: str, data: dict[str, Any],
    ) -> None:
        """Patch an existing synthetic_files row.

        Used by the realism edit-in-place flow (stage 3b): bumps
        ``last_body``, ``content_hash``, ``last_modified``, and
        ``edit_count``.  No-op when *uuid* doesn't exist (the row may
        have been pruned between pick and apply).
        """
        raise NotImplementedError

    async def list_synthetic_files(
        self,
        *,
        decky_uuid: Optional[str] = None,
        persona: Optional[str] = None,
        content_class: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Paginated synthetic_files newest-first.

        Optional filters narrow to one decky, persona, and/or content
        class — used by the dashboard's "files this decky has grown"
        view.
        """
        raise NotImplementedError

    async def count_synthetic_files(
        self,
        *,
        decky_uuid: Optional[str] = None,
        persona: Optional[str] = None,
        content_class: Optional[str] = None,
    ) -> int:
        """Total synthetic_files matching the same filters as
        :meth:`list_synthetic_files`. Used to drive paginated UI."""
        raise NotImplementedError

    async def get_synthetic_file(
        self, uuid: str,
    ) -> Optional[dict[str, Any]]:
        """Single synthetic_files row by uuid, or ``None``."""
        raise NotImplementedError

    async def get_realism_config(
        self, key: str,
    ) -> Optional[dict[str, Any]]:
        """Read one ``realism_config`` row by key.

        Today only ``key="weights"`` is used; the schema is
        single-row-per-key so future tunables can land without a new
        table. Returns ``None`` when the key has never been set —
        callers fall back to hardcoded defaults in
        :mod:`decnet.realism.planner`.
        """
        raise NotImplementedError

    async def set_realism_config(
        self, key: str, value: str,
    ) -> None:
        """Upsert one ``realism_config`` row. Last-write-wins.

        *value* is opaque JSON text; validation belongs to the API
        layer (the planner only reads what landed)."""
        raise NotImplementedError

    async def pick_random_synthetic_file_for_edit(
        self,
        decky_uuid: str,
        *,
        max_age_days: int = 30,
    ) -> Optional[dict[str, Any]]:
        """Return a random eligible synthetic_files row for re-edit.

        "Eligible" = belongs to *decky_uuid*, last_modified within
        *max_age_days*, content_class supports body-level mutation
        (``note``, ``todo``, ``draft``, ``script``, ``log_*``).
        Returns ``None`` when nothing matches.

        Used by the realism planner's ``action="edit"`` branch
        (stage 3b).
        """
        raise NotImplementedError
