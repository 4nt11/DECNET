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
    async def upsert_session_profile(self, sid, data): await super().upsert_session_profile(sid, data)
    async def get_session_profile(self, sid): await super().get_session_profile(sid)
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
    async def purge_logs_and_bounties(self): await super().purge_logs_and_bounties()
    async def get_attacker_artifacts(self, uuid): await super().get_attacker_artifacts(uuid)
    async def get_attacker_transcripts(self, uuid): await super().get_attacker_transcripts(uuid)
    async def get_session_log(self, sid): await super().get_session_log(sid)
    # DEBT-041 / 3eb67c9 — attacker_intel re-key
    async def find_credential_reuse_candidates(self, min_targets=2): await super().find_credential_reuse_candidates(min_targets); return []
    async def get_attacker_intel_by_uuid(self, u): await super().get_attacker_intel_by_uuid(u)
    async def get_unenriched_attackers(self, limit=100): await super().get_unenriched_attackers(limit)
    async def upsert_attacker_intel(self, d): await super().upsert_attacker_intel(d); return ""
    # Identity resolution (this PR)
    async def get_identity_by_uuid(self, u): await super().get_identity_by_uuid(u)
    async def list_identities(self, limit=50, offset=0): await super().list_identities(limit, offset); return []
    async def count_identities(self): await super().count_identities(); return 0
    async def list_observations_for_identity(self, u, limit=50, offset=0): await super().list_observations_for_identity(u, limit, offset); return []
    async def count_observations_for_identity(self, u): await super().count_observations_for_identity(u); return 0

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
    await dr.upsert_session_profile("sid", {})
    await dr.get_session_profile("sid")
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
    await dr.get_unenriched_attackers()
    await dr.upsert_attacker_intel({"attacker_uuid": "a", "attacker_ip": "1.1.1.1"})
    await dr.get_identity_by_uuid("a")
    await dr.list_identities()
    await dr.count_identities()
    await dr.list_observations_for_identity("a")
    await dr.count_observations_for_identity("a")

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
