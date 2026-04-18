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
    async def get_attacker_by_uuid(self, u): await super().get_attacker_by_uuid(u)
    async def get_attackers(self, **kw): await super().get_attackers(**kw)
    async def get_total_attackers(self, **kw): await super().get_total_attackers(**kw)
    async def get_attacker_commands(self, **kw): await super().get_attacker_commands(**kw)
    async def list_users(self): await super().list_users()
    async def delete_user(self, u): await super().delete_user(u)
    async def update_user_role(self, u, r): await super().update_user_role(u, r)
    async def purge_logs_and_bounties(self): await super().purge_logs_and_bounties()
    async def get_attacker_artifacts(self, uuid): await super().get_attacker_artifacts(uuid)

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
    await dr.get_attacker_by_uuid("a")
    await dr.get_attackers()
    await dr.get_total_attackers()
    await dr.get_attacker_commands(uuid="a")
    await dr.list_users()
    await dr.delete_user("a")
    await dr.update_user_role("a", "admin")
    await dr.purge_logs_and_bounties()
    await dr.get_attacker_artifacts("a")

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
    ]:
        with pytest.raises(NotImplementedError):
            await coro(*args)
