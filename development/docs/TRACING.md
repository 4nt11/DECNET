# Distributed Tracing

OpenTelemetry (OTEL) distributed tracing across all DECNET services. Gated by the `DECNET_DEVELOPER_TRACING` environment variable (off by default). When disabled, zero overhead: no OTEL imports occur, `@traced` returns the original unwrapped function, and no middleware is installed.

## Quick Start

```bash
# 1. Start Jaeger (OTLP receiver on :4317, UI on :16686)
docker compose -f development/docker-compose.otel.yml up -d

# 2. Run DECNET with tracing enabled
DECNET_DEVELOPER_TRACING=true decnet web

# 3. Open Jaeger UI — service name is "decnet"
open http://localhost:16686
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `DECNET_DEVELOPER_TRACING` | `false` | Enable/disable all tracing |
| `DECNET_OTEL_ENDPOINT` | `http://localhost:4317` | OTLP gRPC exporter target |

## Architecture

The core module is `decnet/telemetry.py`. All tracing flows through it.

| Export | Purpose |
|--------|---------|
| `setup_tracing(app)` | Init TracerProvider, instrument FastAPI, enable log-trace correlation |
| `shutdown_tracing()` | Flush and shut down the TracerProvider |
| `get_tracer(component)` | Return an OTEL Tracer or `_NoOpTracer` when disabled |
| `@traced(name)` | Decorator wrapping sync/async functions in spans (no-op when disabled) |
| `wrap_repository(repo)` | Dynamic `__getattr__` proxy adding `db.*` spans to every async method |
| `inject_context(record)` | Embed W3C trace context into a JSON record under `_trace` |
| `extract_context(record)` | Recover trace context from `_trace` and remove it from the record |
| `start_span_with_context(tracer, name, ctx)` | Start a span as child of an extracted context |

**TracerProvider config**: Resource(`service.name=decnet`, `service.version=0.2.0`), `BatchSpanProcessor`, OTLP gRPC exporter.

**When disabled**: `_NoOpTracer` and `_NoOpSpan` stubs are returned. No OTEL SDK packages are imported. The `@traced` decorator returns the original function object at decoration time.

## Pipeline Trace Propagation

The DECNET data pipeline is decoupled through JSON files and the database, which normally breaks trace continuity. Four mechanisms bridge the gaps:

1. **Collector → JSON**: `inject_context()` embeds W3C `traceparent`/`tracestate` into each JSON log record under a `_trace` key.
2. **JSON → Ingester**: `extract_context()` recovers the parent context. The ingester creates `ingester.process_record` as a child span, preserving the collector→ingester parent-child relationship.
3. **Ingester → DB**: The ingester persists the current span's `trace_id` and `span_id` as columns on the `logs` table before calling `repo.add_log()`.
4. **DB → SSE**: The SSE endpoint reads `trace_id`/`span_id` from log rows and creates OTEL **span links** (FOLLOWS_FROM) on `sse.emit_logs`, connecting the read path back to the original ingestion traces.

**Log-trace correlation**: `_TraceContextFilter` (installed by `enable_trace_context()`) injects `otel_trace_id` and `otel_span_id` into Python `LogRecord` objects, bridging structured logs with trace context.

## Span Reference

### API Endpoints (20 spans)

| Span | Endpoint |
|------|----------|
| `api.login` | `POST /auth/login` |
| `api.change_password` | `POST /auth/change-password` |
| `api.get_logs` | `GET /logs` |
| `api.get_logs_histogram` | `GET /logs/histogram` |
| `api.get_bounties` | `GET /bounty` |
| `api.get_attackers` | `GET /attackers` |
| `api.get_attacker_detail` | `GET /attackers/{uuid}` |
| `api.get_attacker_commands` | `GET /attackers/{uuid}/commands` |
| `api.get_stats` | `GET /stats` |
| `api.get_deckies` | `GET /fleet/deckies` |
| `api.deploy_deckies` | `POST /fleet/deploy` |
| `api.mutate_decky` | `POST /fleet/mutate/{decky_id}` |
| `api.update_mutate_interval` | `POST /fleet/mutate-interval/{decky_id}` |
| `api.get_config` | `GET /config` |
| `api.update_deployment_limit` | `PUT /config/deployment-limit` |
| `api.update_global_mutation_interval` | `PUT /config/global-mutation-interval` |
| `api.create_user` | `POST /config/users` |
| `api.delete_user` | `DELETE /config/users/{uuid}` |
| `api.update_user_role` | `PUT /config/users/{uuid}/role` |
| `api.reset_user_password` | `PUT /config/users/{uuid}/password` |
| `api.reinit` | `POST /config/reinit` |
| `api.get_health` | `GET /health` |
| `api.stream_events` | `GET /stream` |

### DB Layer (dynamic)

Every async method on `BaseRepository` is automatically wrapped by `TracedRepository` as `db.<method_name>` (e.g. `db.add_log`, `db.get_attackers`, `db.upsert_attacker`).

### Collector

| Span | Type |
|------|------|
| `collector.stream_container` | `@traced` |
| `collector.event` | inline |

### Ingester

| Span | Type |
|------|------|
| `ingester.process_record` | inline (with parent context) |
| `ingester.extract_bounty` | `@traced` |

### Profiler

| Span | Type |
|------|------|
| `profiler.incremental_update` | `@traced` |
| `profiler.update_profiles` | `@traced` |
| `profiler.process_ip` | inline |
| `profiler.timing_stats` | `@traced` |
| `profiler.classify_behavior` | `@traced` |
| `profiler.detect_tools_from_headers` | `@traced` |
| `profiler.phase_sequence` | `@traced` |
| `profiler.sniffer_rollup` | `@traced` |
| `profiler.build_behavior_record` | `@traced` |
| `profiler.behavior_summary` | inline |

### Sniffer

| Span | Type |
|------|------|
| `sniffer.worker` | `@traced` |
| `sniffer.sniff_loop` | `@traced` |
| `sniffer.tcp_syn_fingerprint` | inline |
| `sniffer.tls_client_hello` | inline |
| `sniffer.tls_server_hello` | inline |
| `sniffer.tls_certificate` | inline |
| `sniffer.parse_client_hello` | `@traced` |
| `sniffer.parse_server_hello` | `@traced` |
| `sniffer.parse_certificate` | `@traced` |
| `sniffer.ja3` | `@traced` |
| `sniffer.ja3s` | `@traced` |
| `sniffer.ja4` | `@traced` |
| `sniffer.ja4s` | `@traced` |
| `sniffer.session_resumption_info` | `@traced` |
| `sniffer.p0f_guess_os` | `@traced` |
| `sniffer.write_event` | `@traced` |

### Prober

| Span | Type |
|------|------|
| `prober.worker` | `@traced` |
| `prober.discover_attackers` | `@traced` |
| `prober.probe_cycle` | `@traced` |
| `prober.jarm_phase` | `@traced` |
| `prober.hassh_phase` | `@traced` |
| `prober.tcpfp_phase` | `@traced` |
| `prober.jarm_hash` | `@traced` |
| `prober.jarm_send_probe` | `@traced` |
| `prober.hassh_server` | `@traced` |
| `prober.hassh_ssh_connect` | `@traced` |
| `prober.tcp_fingerprint` | `@traced` |
| `prober.tcpfp_send_syn` | `@traced` |

### Engine

| Span | Type |
|------|------|
| `engine.deploy` | `@traced` |
| `engine.teardown` | `@traced` |
| `engine.compose_with_retry` | `@traced` |

### Mutator

| Span | Type |
|------|------|
| `mutator.mutate_decky` | `@traced` |
| `mutator.mutate_all` | `@traced` |
| `mutator.watch_loop` | `@traced` |

### Correlation

| Span | Type |
|------|------|
| `correlation.ingest_file` | `@traced` |
| `correlation.ingest_file.summary` | inline |
| `correlation.traversals` | `@traced` |
| `correlation.report_json` | `@traced` |
| `correlation.traversal_syslog_lines` | `@traced` |

### Logging

| Span | Type |
|------|------|
| `logging.init_file_handler` | `@traced` |
| `logging.probe_log_target` | `@traced` |

### SSE

| Span | Type |
|------|------|
| `sse.emit_logs` | inline (with span links to ingestion traces) |

## Adding New Traces

```python
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer

# Decorator (preferred for entire functions)
@_traced("component.operation")
async def my_function():
    ...

# Inline (for sub-sections within a function)
with _get_tracer("component").start_as_current_span("component.sub_op") as span:
    span.set_attribute("key", "value")
    ...
```

Naming convention: `component.operation` (e.g. `prober.jarm_hash`, `profiler.timing_stats`).

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No traces in Jaeger | `DECNET_DEVELOPER_TRACING=true`? Jaeger running on port 4317? |
| `ImportError` on OTEL packages | Run `pip install -e ".[dev]"` (OTEL is in optional deps) |
| Partial traces (ingester orphaned) | Verify `_trace` key present in JSON log file records |
| SSE spans have no links | Confirm `trace_id`/`span_id` columns exist in `logs` table |
| Performance concern | BatchSpanProcessor adds ~1ms per span; zero overhead when disabled |
