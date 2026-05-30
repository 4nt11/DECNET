# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Mock test for BaseRepository to ensure coverage of abstract pass lines.
"""

import pytest
from decnet.web.db.repository import BaseRepository

class DummyRepo(BaseRepository):
    async def initialize(self) -> None: await super().initialize()
    async def add_log(self, data): await super().add_log(data)
    async def get_logs(self, **kw): await super().get_logs(**kw)
    async def get_total_logs(self, **kw): await super().get_total_logs(**kw)
    async def get_stats_summary(self): await super().get_stats_summary()
    async def get_deckies(self): await super().get_deckies()
    async def get_user_by_username(self, u): await super().get_user_by_username(u)
    async def get_user_by_uuid(self, u): await super().get_user_by_uuid(u)
    async def create_user(self, d): await super().create_user(d)
    async def update_user_password(self, *a, **kw): await super().update_user_password(*a, **kw)
    async def add_bounty(self, d): await super().add_bounty(d)
    async def get_bounties(self, **kw): await super().get_bounties(**kw)
    async def get_total_bounties(self, **kw): await super().get_total_bounties(**kw)
    async def upsert_credential(self, d): await super().upsert_credential(d); return 0
    async def get_credentials(self, **kw): await super().get_credentials(**kw)
    async def get_total_credentials(self, **kw): await super().get_total_credentials(**kw)
    async def get_credentials_for_attacker(self, ip): await super().get_credentials_for_attacker(ip)
    async def get_credential_attempts_for_secret(self, h): await super().get_credential_attempts_for_secret(h)
    async def upsert_credential_reuse(self, **kw): await super().upsert_credential_reuse(**kw); return None
    async def list_credential_reuses(self, **kw): await super().list_credential_reuses(**kw); return (0, [])
    async def get_credential_reuse_by_id(self, i): await super().get_credential_reuse_by_id(i)
    async def update_credential_attacker_uuid(self, ip, u): await super().update_credential_attacker_uuid(ip, u); return 0
    async def get_state(self, k): await super().get_state(k)
    async def set_state(self, k, v): await super().set_state(k, v)
    async def get_max_log_id(self): await super().get_max_log_id()
    async def get_logs_after_id(self, last_id, limit=500): await super().get_logs_after_id(last_id, limit)
    async def get_all_bounties_by_ip(self): await super().get_all_bounties_by_ip()
    async def get_bounties_for_ips(self, ips): await super().get_bounties_for_ips(ips)
    async def upsert_attacker(self, d): await super().upsert_attacker(d); return ""
    async def upsert_attacker_behavior(self, u, d): await super().upsert_attacker_behavior(u, d)
    async def get_attacker_behavior(self, u): await super().get_attacker_behavior(u)
    async def get_behaviors_for_ips(self, ips): await super().get_behaviors_for_ips(ips)
    # BEHAVE-SHELL observations (DEBT-050 / BEHAVE-INTEGRATION.md Phase 1)
    async def upsert_observation(self, data): await super().upsert_observation(data); return ""
    async def latest_observation_per_primitive(self, attacker_uuid): await super().latest_observation_per_primitive(attacker_uuid); return {}
    async def observations_time_series(self, attacker_uuid, primitive): await super().observations_time_series(attacker_uuid, primitive); return []
    async def observations_for_identity_primitive(self, identity_uuid, primitive):
        await super().observations_for_identity_primitive(identity_uuid, primitive)
        return []
    # Attribution engine v0 (ATTRIBUTION-ENGINE.md Phase 1)
    async def ensure_stub_identity_for_attacker(self, attacker_uuid):
        await super().ensure_stub_identity_for_attacker(attacker_uuid)
        return None
    async def upsert_attribution_state(self, data):
        await super().upsert_attribution_state(data)
    async def get_attribution_state(self, identity_uuid, primitive):
        await super().get_attribution_state(identity_uuid, primitive)
        return None
    async def get_attribution_state_for_identity(self, identity_uuid):
        await super().get_attribution_state_for_identity(identity_uuid)
        return []
    async def list_multi_actor_identities(self):
        await super().list_multi_actor_identities()
        return []
    async def increment_smtp_target(self, u, d): await super().increment_smtp_target(u, d)
    async def list_smtp_targets(self, u): await super().list_smtp_targets(u)
    async def get_attacker_stored_mail(self, u): await super().get_attacker_stored_mail(u)
    async def smtp_target_seen(self, d): await super().smtp_target_seen(d)
    async def get_attacker_by_uuid(self, u): await super().get_attacker_by_uuid(u)
    async def get_attackers(self, **kw): await super().get_attackers(**kw)
    async def get_total_attackers(self, **kw): await super().get_total_attackers(**kw)
    async def get_attacker_commands(self, **kw): await super().get_attacker_commands(**kw)
    async def list_users(self): await super().list_users()
    async def delete_user(self, u): await super().delete_user(u)
    async def update_user_role(self, u, r): await super().update_user_role(u, r)
    async def revoke_token(self, j, u, e): await super().revoke_token(j, u, e)
    async def is_token_revoked(self, j): await super().is_token_revoked(j); return False
    async def set_tokens_valid_from(self, u, ts): await super().set_tokens_valid_from(u, ts)
    async def purge_logs_and_bounties(self): await super().purge_logs_and_bounties()
    async def get_attacker_artifacts(self, uuid): await super().get_attacker_artifacts(uuid)
    async def get_attacker_transcripts(self, uuid): await super().get_attacker_transcripts(uuid)
    async def get_session_log(self, sid): await super().get_session_log(sid)
    # DEBT-041 / 3eb67c9 — attacker_intel re-key
    async def find_credential_reuse_candidates(self, min_targets=2): await super().find_credential_reuse_candidates(min_targets); return []
    async def get_attacker_intel_by_uuid(self, u): await super().get_attacker_intel_by_uuid(u)
    async def get_attacker_intel_row_by_uuid(self, u): await super().get_attacker_intel_row_by_uuid(u)
    async def get_unenriched_attackers(self, limit=100): await super().get_unenriched_attackers(limit)
    async def upsert_attacker_intel(self, d): await super().upsert_attacker_intel(d); return ""
    # Identity resolution (this PR)
    async def get_identity_by_uuid(self, u): await super().get_identity_by_uuid(u)
    async def list_identities(self, limit=50, offset=0): await super().list_identities(limit, offset); return []
    async def count_identities(self): await super().count_identities(); return 0
    async def list_observations_for_identity(self, u, limit=50, offset=0): await super().list_observations_for_identity(u, limit, offset); return []
    async def count_observations_for_identity(self, u): await super().count_observations_for_identity(u); return 0
    async def list_attackers_for_clustering(self, limit=None): await super().list_attackers_for_clustering(limit); return []
    async def create_attacker_identity(self, row): await super().create_attacker_identity(row); return ""
    async def set_attacker_identity_id(self, a, i): await super().set_attacker_identity_id(a, i)
    async def list_all_identities(self): await super().list_all_identities(); return []
    async def update_identity_merged_into(self, u, w): await super().update_identity_merged_into(u, w)
    async def update_identity_fingerprints(self, u, *, ja3_hashes=None, hassh_hashes=None, tls_cert_sha256=None):
        await super().update_identity_fingerprints(u, ja3_hashes=ja3_hashes, hassh_hashes=hassh_hashes, tls_cert_sha256=tls_cert_sha256)
    # Campaign clustering (this PR)
    async def get_campaign_by_uuid(self, u): await super().get_campaign_by_uuid(u)
    async def list_campaigns(self, limit=50, offset=0): await super().list_campaigns(limit, offset); return []
    async def count_campaigns(self): await super().count_campaigns(); return 0
    async def list_identities_for_campaign(self, u, limit=50, offset=0): await super().list_identities_for_campaign(u, limit, offset); return []
    async def count_identities_for_campaign(self, u): await super().count_identities_for_campaign(u); return 0
    async def list_identities_for_clustering(self, limit=None): await super().list_identities_for_clustering(limit); return []
    async def create_campaign(self, row): await super().create_campaign(row); return ""
    async def set_identity_campaign_id(self, i, c): await super().set_identity_campaign_id(i, c)
    async def list_all_campaigns(self): await super().list_all_campaigns(); return []
    async def update_campaign_merged_into(self, u, w): await super().update_campaign_merged_into(u, w)
    # Pre-existing abstract surface that DummyRepo never stubbed —
    # added here so the coverage test exercises the full BaseRepository
    # contract.
    async def get_log_histogram(self, *a, **kw):
        await super().get_log_histogram(*a, **kw); return []
    async def has_observations_for_evidence(self, evidence_ref):
        await super().has_observations_for_evidence(evidence_ref); return False
    async def list_observations_by_attacker(self, attacker_uuid):
        await super().list_observations_by_attacker(attacker_uuid); return []
    async def get_all_observations_for_export(self):
        await super().get_all_observations_for_export(); return {}
    async def get_fingerprint_bounties_by_ip(self, ip):
        await super().get_fingerprint_bounties_by_ip(ip); return []
    async def get_all_fingerprint_bounties_for_export(self):
        await super().get_all_fingerprint_bounties_for_export(); return {}
    async def get_attacker_uuid_by_ip(self, ip):
        await super().get_attacker_uuid_by_ip(ip); return None
    # TTP rollup surface (TTP_TAGGING.md)
    async def insert_tags(self, rows): await super().insert_tags(rows); return 0
    async def list_techniques_by_identity(self, uuid):
        await super().list_techniques_by_identity(uuid); return []
    async def list_techniques_by_attacker(self, uuid):
        await super().list_techniques_by_attacker(uuid); return []
    async def list_techniques_by_campaign(self, uuid):
        await super().list_techniques_by_campaign(uuid); return []
    async def list_techniques_by_session(self, sid):
        await super().list_techniques_by_session(sid); return []
    async def list_tags_by_scope_and_technique(self, **kw):
        await super().list_tags_by_scope_and_technique(**kw); return []
    async def list_distinct_techniques(self):
        await super().list_distinct_techniques(); return []
    async def bump_attacker_ipv6_leak(self, attacker_uuid, identity_uuid, evidence):
        await super().bump_attacker_ipv6_leak(attacker_uuid, identity_uuid, evidence)
    async def list_ttp_tags_by_attacker(self, uuid, limit=2000):
        return []
    async def list_attacker_commands_deduped(self, uuid):
        return []
    async def get_all_ttp_rollups_for_export(self):
        return {}
    # Iter helpers — async generators, can't `await super()` on them
    # because the base raises in the body before any yield. Just yield
    # nothing so the consumer's ``async for`` exits cleanly.
    async def iter_attacker_commands_since(self, since):
        return
        yield  # unreachable, marks the function as a generator
    async def iter_canary_triggers_since(self, since):
        return
        yield
    # DeckyLifecycle surface
    async def create_lifecycle(self, data):
        await super().create_lifecycle(data); return ""
    async def update_lifecycle(self, lifecycle_id, fields):
        await super().update_lifecycle(lifecycle_id, fields)
    async def get_lifecycle_by_ids(self, ids):
        await super().get_lifecycle_by_ids(ids); return []
    async def find_open_lifecycle(self, decky_name, operation, host_uuid=None):
        await super().find_open_lifecycle(decky_name, operation, host_uuid); return None
    async def sweep_stale_lifecycle(self, older_than, reason):
        await super().sweep_stale_lifecycle(older_than, reason); return 0

@pytest.mark.asyncio
async def test_base_repo_coverage():
    dr = DummyRepo()
    # Call all to hit 'pass' statements
    await dr.initialize()
    await dr.add_log({})
    await dr.get_logs()
    await dr.get_total_logs()
    await dr.get_stats_summary()
    await dr.get_deckies()
    await dr.get_user_by_username("a")
    await dr.get_user_by_uuid("a")
    await dr.create_user({})
    await dr.update_user_password("a", "b")
    await dr.add_bounty({})
    await dr.get_bounties()
    await dr.get_total_bounties()
    await dr.upsert_credential({})
    await dr.get_credentials()
    await dr.get_total_credentials()
    await dr.get_credentials_for_attacker("1.2.3.4")
    await dr.get_credential_attempts_for_secret("abc")
    await dr.upsert_credential_reuse(
        secret_sha256="x", secret_kind="plaintext", principal=None,
        attacker_uuid=None, attacker_ip="1.2.3.4", decky="d", service="ssh",
        attempt_count=1, ts=None,
    )
    await dr.list_credential_reuses()
    await dr.get_credential_reuse_by_id("a")
    await dr.update_credential_attacker_uuid("1.2.3.4", "u")
    await dr.get_state("k")
    await dr.set_state("k", "v")
    await dr.get_max_log_id()
    await dr.get_logs_after_id(0)
    await dr.get_all_bounties_by_ip()
    await dr.get_bounties_for_ips({"1.1.1.1"})
    await dr.upsert_attacker({})
    await dr.upsert_attacker_behavior("a", {})
    await dr.get_attacker_behavior("a")
    await dr.get_behaviors_for_ips({"1.1.1.1"})
    # Observation surface — bases raise NotImplementedError.
    with pytest.raises(NotImplementedError):
        await dr.upsert_observation({})
    with pytest.raises(NotImplementedError):
        await dr.latest_observation_per_primitive("a")
    with pytest.raises(NotImplementedError):
        await dr.observations_time_series("a", "motor.input_modality")
    # observations_for_identity_primitive + attribution engine v0
    with pytest.raises(NotImplementedError):
        await dr.observations_for_identity_primitive("i", "motor.input_modality")
    with pytest.raises(NotImplementedError):
        await dr.ensure_stub_identity_for_attacker("a")
    with pytest.raises(NotImplementedError):
        await dr.upsert_attribution_state({})
    with pytest.raises(NotImplementedError):
        await dr.get_attribution_state("i", "motor.input_modality")
    with pytest.raises(NotImplementedError):
        await dr.get_attribution_state_for_identity("i")
    with pytest.raises(NotImplementedError):
        await dr.list_multi_actor_identities()
    await dr.increment_smtp_target("uuid", "corp.com")
    await dr.list_smtp_targets("uuid")
    await dr.get_attacker_stored_mail("uuid")
    await dr.smtp_target_seen("corp.com")
    await dr.get_attacker_by_uuid("a")
    await dr.get_attackers()
    await dr.get_total_attackers()
    await dr.get_attacker_commands(uuid="a")
    await dr.list_users()
    await dr.delete_user("a")
    await dr.update_user_role("a", "admin")
    await dr.purge_logs_and_bounties()
    await dr.get_attacker_artifacts("a")
    await dr.get_attacker_transcripts("a")
    await dr.get_session_log("a")
    await dr.find_credential_reuse_candidates()
    await dr.get_attacker_intel_by_uuid("a")
    await dr.get_attacker_intel_row_by_uuid("a")
    await dr.get_unenriched_attackers()
    await dr.upsert_attacker_intel({"attacker_uuid": "a", "attacker_ip": "1.1.1.1"})
    await dr.get_identity_by_uuid("a")
    await dr.list_identities()
    await dr.count_identities()
    await dr.list_observations_for_identity("a")
    await dr.count_observations_for_identity("a")
    await dr.list_attackers_for_clustering()
    await dr.create_attacker_identity({"uuid": "i"})
    await dr.set_attacker_identity_id("a", "i")
    await dr.list_all_identities()
    await dr.update_identity_merged_into("a", "b")
    await dr.update_identity_merged_into("a", None)
    await dr.update_identity_fingerprints("a", ja3_hashes='["x"]', hassh_hashes=None, tls_cert_sha256='["y"]')
    await dr.get_campaign_by_uuid("a")
    await dr.list_campaigns()
    await dr.count_campaigns()
    await dr.list_identities_for_campaign("a")
    await dr.count_identities_for_campaign("a")
    await dr.list_identities_for_clustering()
    await dr.create_campaign({"uuid": "c"})
    await dr.set_identity_campaign_id("i", "c")
    await dr.set_identity_campaign_id("i", None)
    await dr.list_all_campaigns()
    await dr.update_campaign_merged_into("c", "d")
    await dr.update_campaign_merged_into("c", None)

    # Pre-existing abstract surface. get_log_histogram's base body
    # is ``pass`` (returns None), the rest raise NotImplementedError.
    from datetime import datetime, timezone
    await dr.get_log_histogram()
    # Token-revocation surface (JWT denylist + bulk cutoff).
    await dr.revoke_token("jti-x", "user-x", datetime.now(timezone.utc))
    await dr.is_token_revoked("jti-x")
    await dr.set_tokens_valid_from("user-x", datetime.now(timezone.utc))
    with pytest.raises(NotImplementedError):
        await dr.has_observations_for_evidence("shard:x#1")
    with pytest.raises(NotImplementedError):
        await dr.list_observations_by_attacker("a")
    with pytest.raises(NotImplementedError):
        await dr.get_all_observations_for_export()
    with pytest.raises(NotImplementedError):
        await dr.get_fingerprint_bounties_by_ip("1.1.1.1")
    with pytest.raises(NotImplementedError):
        await dr.get_all_fingerprint_bounties_for_export()
    with pytest.raises(NotImplementedError):
        await dr.get_attacker_uuid_by_ip("1.1.1.1")
    with pytest.raises(NotImplementedError):
        await dr.insert_tags([])
    with pytest.raises(NotImplementedError):
        await dr.list_techniques_by_identity("i")
    with pytest.raises(NotImplementedError):
        await dr.list_techniques_by_attacker("a")
    with pytest.raises(NotImplementedError):
        await dr.list_techniques_by_campaign("c")
    with pytest.raises(NotImplementedError):
        await dr.list_techniques_by_session("s")
    with pytest.raises(NotImplementedError):
        await dr.list_tags_by_scope_and_technique(
            scope="identity", uuid="i", technique_id="T1059",
        )
    with pytest.raises(NotImplementedError):
        await dr.list_distinct_techniques()
    with pytest.raises(NotImplementedError):
        await dr.bump_attacker_ipv6_leak("uuid-1", None, {})
    with pytest.raises(NotImplementedError):
        from decnet.web.db.repository import BaseRepository
        await BaseRepository.list_ttp_tags_by_attacker(dr, "a")
    with pytest.raises(NotImplementedError):
        await BaseRepository.list_attacker_commands_deduped(dr, "a")
    with pytest.raises(NotImplementedError):
        await BaseRepository.get_all_ttp_rollups_for_export(dr)
    # Iter helpers: just consume the empty generator.
    now = datetime.now(timezone.utc)
    async for _ in dr.iter_attacker_commands_since(now):
        pass
    async for _ in dr.iter_canary_triggers_since(now):
        pass

    # Swarm methods: default NotImplementedError on BaseRepository.  Covering
    # them here keeps the coverage contract honest for the swarm CRUD surface.
    for coro, args in [
        (dr.add_swarm_host, ({},)),
        (dr.get_swarm_host_by_name, ("w",)),
        (dr.get_swarm_host_by_uuid, ("u",)),
        (dr.list_swarm_hosts, ()),
        (dr.update_swarm_host, ("u", {})),
        (dr.delete_swarm_host, ("u",)),
        (dr.upsert_decky_shard, ({},)),
        (dr.list_decky_shards, ()),
        (dr.delete_decky_shards_for_host, ("u",)),
        (dr.create_lifecycle, ({"decky_name": "d", "operation": "deploy"},)),
        (dr.update_lifecycle, ("id", {})),
        (dr.get_lifecycle_by_ids, (["id"],)),
        (dr.find_open_lifecycle, ("d", "deploy")),
        (dr.sweep_stale_lifecycle, (datetime.now(timezone.utc), "reason")),
        (dr.create_topology, ({},)),
        (dr.get_topology, ("t",)),
        (dr.list_topologies, ()),
        (dr.update_topology_status, ("t", "active")),
        (dr.delete_topology_cascade, ("t",)),
        (dr.add_lan, ({},)),
        (dr.update_lan, ("l", {})),
        (dr.list_lans_for_topology, ("t",)),
        (dr.add_topology_decky, ({},)),
        (dr.update_topology_decky, ("d", {})),
        (dr.list_topology_deckies, ("t",)),
        (dr.add_topology_edge, ({},)),
        (dr.list_topology_edges, ("t",)),
        (dr.list_topology_status_events, ("t",)),
    ]:
        with pytest.raises(NotImplementedError):
            await coro(*args)
