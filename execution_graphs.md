# DECNET Execution Graphs

These graphs illustrate the logical flow of execution within the DECNET framework, showing how high-level commands and API requests trigger secondary processes and subsystem interactions.

## 1. Deployment & Teardown Flow
This flow shows the orchestration from a CLI `deploy` command down to network setup and container instantiation.

```mermaid
graph TD
    CLI_Deploy([cli.deploy]) --> INI[ini_loader.load_ini]
    CLI_Deploy --> NET_Detect[network.detect_interface]
    CLI_Deploy --> FleetBuild[fleet.build_deckies_from_ini]
    
    FleetBuild --> Archetype[archetypes.get_archetype]
    FleetBuild --> Distro[distros.get_distro]
    
    CLI_Deploy --> Engine_Deploy[engine.deployer.deploy]
    
    Engine_Deploy --> IP_Alloc[network.allocate_ips]
    Engine_Deploy --> NET_Setup[network.setup_host_macvlan]
    Engine_Deploy --> Compose_Gen[composer.write_compose]
    Engine_Deploy --> Docker_Up[engine.deployer._compose_with_retry]
    
    CLI_Teardown([cli.teardown]) --> Engine_Teardown[engine.deployer.teardown]
    Engine_Teardown --> NET_Cleanup[network.teardown_host_macvlan]
    Engine_Teardown --> Docker_Down[engine.deployer._compose]
```

## 2. Mutation & Monitoring Flow
How DECNET maintains deception by periodically changing decoy identities and monitoring activities.

```mermaid
graph LR
    subgraph Periodic_Process
        CLI_Mutate([cli.mutate]) --> Mutate_Loop[mutator.engine.run_watch_loop]
    end
    
    Mutate_Loop --> Mutate_All[mutator.engine.mutate_all]
    Mutate_All --> Mutate_Decky[mutator.engine.mutate_decky]
    
    Mutate_Decky --> Get_New_Identity[archetypes.get_archetype]
    Mutate_Decky --> Rewrite_Compose[composer.write_compose]
    Mutate_Decky --> Restart_Container[engine.deployer._compose_with_retry]
    
    subgraph Log_Collection
        CLI_Collect([cli.collect]) --> Worker[collector.worker.log_collector_worker]
        Worker --> Stream[collector.worker._stream_container]
        Stream --> Parse[collector.worker.parse_rfc5424]
    end
```

## 3. Web API Flow (Fleet Management)
How the Web UI interacts with the underlying systems via the FastAPI router.

```mermaid
graph TD
    Web_UI[Web Dashboard] --> API_Deploy[web.router.fleet.deploy_deckies]
    Web_UI --> API_Mutate[web.router.fleet.mutate_decky]
    Web_UI --> API_Stream[web.router.stream.stream_events]
    
    API_Deploy --> FleetBuild[fleet.build_deckies_from_ini]
    API_Mutate --> Mutator[mutator.engine.mutate_decky]
    
    API_Stream --> DB_Pull[web.db.sqlite.repository.get_logs_after_id]
    DB_Pull --> SQLite[(SQLite Database)]
```
