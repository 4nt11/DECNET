# DECNET Test Coverage Report

> **Last Updated:** 2026-04-12  
> **Total Coverage:** 93% ✅  
> **Total Tests:** 1074 Passed ✅

## 📊 Full Coverage Table

```text
Name                                             Stmts   Miss  Cover   Missing
------------------------------------------------------------------------------
decnet/__init__.py                                   0      0   100%
decnet/archetypes.py                                21      0   100%
decnet/cli.py                                      265     43    84%   62-63, 136, 138, 146-149, 163-165, 179-180, 198-199, 223-223, 251-252, 255-260, 282-283, 385-386, 390-393, 398, 400-401, 409-410, 418-419, 458-461
decnet/collector/__init__.py                         2      0   100%
decnet/collector/worker.py                         110      3    97%   196-198
decnet/composer.py                                  36      3    92%   110-112
decnet/config.py                                    38      0   100%
decnet/correlation/__init__.py                       4      0   100%
decnet/correlation/engine.py                        62      0   100%
decnet/correlation/graph.py                         37      0   100%
decnet/correlation/parser.py                        47      2    96%   98-99
decnet/custom_service.py                            17      0   100%
decnet/distros.py                                   26      1    96%   110
decnet/engine/__init__.py                            2      0   100%
decnet/engine/deployer.py                          147      8    95%   42, 45, 177-182
decnet/env.py                                       38      7    82%   17-18, 20, 29, 37-42
decnet/fleet.py                                     83      1    99%   136
decnet/ini_loader.py                               111      5    95%   158-161, 205
decnet/logging/__init__.py                           0      0   100%
decnet/logging/file_handler.py                      30      0   100%
decnet/logging/forwarder.py                         13      0   100%
decnet/logging/syslog_formatter.py                  34      0   100%
decnet/mutator/__init__.py                           2      0   100%
decnet/mutator/engine.py                            80     10    88%   43, 50-51, 116-122
decnet/network.py                                  106      0   100%
decnet/os_fingerprint.py                             8      0   100%
decnet/services/__init__.py                          0      0   100%
decnet/services/base.py                              7      1    86%   42
decnet/services/conpot.py                           13      0   100%
decnet/services/docker_api.py                       14      0   100%
decnet/services/elasticsearch.py                    14      0   100%
decnet/services/ftp.py                              14      0   100%
decnet/services/http.py                             31      3    90%   46-48
decnet/services/imap.py                             14      0   100%
decnet/services/k8s.py                              14      0   100%
decnet/services/ldap.py                             14      0   100%
decnet/services/llmnr.py                            14      0   100%
decnet/services/mongodb.py                          14      0   100%
decnet/services/mqtt.py                             14      0   100%
decnet/services/mssql.py                            14      0   100%
decnet/services/mysql.py                            17      0   100%
decnet/services/pop3.py                             14      0   100%
decnet/services/postgres.py                         14      0   100%
decnet/services/rdp.py                              14      0   100%
decnet/services/redis.py                            19      0   100%
decnet/services/registry.py                         31      3    90%   38-39, 45
decnet/services/sip.py                              14      0   100%
decnet/services/smb.py                              14      0   100%
decnet/services/smtp.py                             19      0   100%
decnet/services/smtp_relay.py                       19      0   100%
decnet/services/snmp.py                             14      0   100%
decnet/services/ssh.py                              15      0   100%
decnet/services/telnet.py                           15      1    93%   36
decnet/services/tftp.py                             14      0   100%
decnet/services/vnc.py                              14      0   100%
decnet/web/api.py                                   39      2    95%   32, 44
decnet/web/auth.py                                  23      0   100%
decnet/web/db/models.py                             41      0   100%
decnet/web/db/repository.py                         42      0   100%
decnet/web/db/sqlite/database.py                    21      4    81%   12, 29-33
decnet/web/db/sqlite/repository.py                 168     20    88%   53-54, 58-74, 81, 87-88, 112-113, 304, 306-307, 339-340
decnet/web/dependencies.py                          39      0   100%
decnet/web/ingester.py                              55      2    96%   66-67
decnet/web/router/__init__.py                       24      0   100%
decnet/web/router/auth/api_change_pass.py           14      0   100%
decnet/web/router/auth/api_login.py                 15      0   100%
decnet/web/router/bounty/api_get_bounties.py        10      0   100%
decnet/web/router/fleet/api_deploy_deckies.py       50     38    24%   18-79
decnet/web/router/fleet/api_get_deckies.py           7      0   100%
decnet/web/router/fleet/api_mutate_decky.py         10      0   100%
decnet/web/router/fleet/api_mutate_interval.py      17      0   100%
decnet/web/router/logs/api_get_histogram.py          7      1    86%   19
decnet/web/router/logs/api_get_logs.py              11      0   100%
decnet/web/router/stats/api_get_stats.py             8      0   100%
decnet/web/router/stream/api_stream_events.py       44     21    52%   36-68, 70
------------------------------------------------------------------------------
TOTAL                                             2402    179    93%
```

## 📋 Future Coverage Plan (Missing Tests)

### 🔴 High Priority: `api_deploy_deckies.py` (24%)
- **Problem:** Requires live Docker/MACVLAN orchestration.
- **Plan:** 
    - Implement a mock engine specifically for the API route test that validates the `config` object without calling Docker.
    - Integration testing using **Docker-in-Docker (DinD)** once CI infrastructure is ready.

### 🟡 Medium Priority: `api_stream_events.py` (52%)
- **Problem:** Infinite event loop causes test hangs.
- **Plan:** 
    - Test frame headers/auth (Done).
    - Refactor generator to yield a fixed test set or use a loop-breaker for testing.

### 🟢 Low Priority: Misc. Service Logic
- **Modules:** `services/http.py` (90%), `services/telnet.py` (93%), `distros.py` (96%).
- **Plan:** Add edge-case unit tests for custom service configurations and invalid distro slugs.
