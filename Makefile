PYTEST     := .311/bin/pytest
FAIL_FAST  ?= 1
ARGS       :=

# addopts in pyproject.toml already provides -v -q -x -n 4 --dist load.
# Unit suites inherit that; special suites clear it with --override-ini.
UNIT_FLAGS  := --timeout=30 --timeout-method=thread
SEQ_FLAGS   := --override-ini="addopts=-v -x" -n logical --timeout=120 --timeout-method=thread
FUZZ_FLAGS  := --override-ini="addopts=-v -x" -n logical -m fuzz \
	--ignore=tests/api/test_schemathesis.py \
	--ignore=tests/api/test_schemathesis_agent.py \
	--ignore=tests/api/test_schemathesis_swarm.py \
	--ignore=tests/api/test_schemathesis_ttp.py
SCHEMA_QUICK ?= 0
SCHEMA_FLAGS := --override-ini="addopts=-v -x" -n 4 -m fuzz --timeout=600 --timeout-method=thread
BENCH_FLAGS := --override-ini="addopts=-v" -p no:xdist --benchmark-only -m bench

# ── Unit suites (xdist, 30s timeout) ─────────────────────────────────────────

.PHONY: test-core
test-core:
	$(PYTEST) tests/core tests/config tests/factories tests/fixtures $(UNIT_FLAGS) $(ARGS)

.PHONY: test-web
test-web:
	$(PYTEST) tests/web tests/services $(UNIT_FLAGS) $(ARGS)

.PHONY: test-db
test-db:
	$(PYTEST) tests/db tests/vectorstore $(UNIT_FLAGS) $(ARGS)

.PHONY: test-bus
test-bus:
	$(PYTEST) tests/bus tests/logging tests/telemetry $(UNIT_FLAGS) $(ARGS)

.PHONY: test-ttp
test-ttp:
	$(PYTEST) tests/ttp $(UNIT_FLAGS) $(ARGS)

.PHONY: test-intel
test-intel:
	$(PYTEST) tests/intel tests/asn tests/geoip $(UNIT_FLAGS) $(ARGS)

.PHONY: test-analysis
test-analysis:
	$(PYTEST) tests/clustering tests/correlation $(UNIT_FLAGS) $(ARGS)

.PHONY: test-infra
test-infra:
	$(PYTEST) tests/agent tests/collector tests/sniffer tests/profiler $(UNIT_FLAGS) $(ARGS)

.PHONY: test-fleet
test-fleet:
	$(PYTEST) tests/fleet tests/swarm tests/topology tests/orchestrator tests/deploy tests/updater $(UNIT_FLAGS) $(ARGS)

.PHONY: test-cli
test-cli:
	$(PYTEST) tests/cli tests/engine tests/mutator tests/realism $(UNIT_FLAGS) $(ARGS)

.PHONY: test-features
test-features:
	$(PYTEST) tests/canary tests/artifacts tests/webhook tests/decky_io tests/prober $(UNIT_FLAGS) $(ARGS)

# ── Go and React suites ───────────────────────────────────────────────────────

_GO_MODULES := \
	decnet/templates/_caddy_modules/decnetfp \
	decnet/templates/http/_caddy_modules/decnetfp \
	decnet/templates/https/_caddy_modules/decnetfp

.PHONY: test-go
test-go:
	@failed=""; \
	for mod in $(_GO_MODULES); do \
		echo "=== go test: $$mod ==="; \
		if (cd "$$mod" && go test ./...); then \
			echo "[PASS] $$mod"; \
		else \
			echo "[FAIL] $$mod"; \
			failed="$$failed $$mod"; \
			if [ "$(FAIL_FAST)" = "1" ]; then exit 1; fi; \
		fi; \
	done; \
	[ -z "$$failed" ]

.PHONY: test-react
test-react:
	cd decnet_web && npm run test:run $(ARGS)

# ── Special suites (sequential, longer timeout) ───────────────────────────────

.PHONY: test-live
test-live:
	$(PYTEST) tests/live -m live $(SEQ_FLAGS) $(ARGS)

.PHONY: test-api
test-api:
	$(PYTEST) tests/api $(SEQ_FLAGS) $(ARGS)

.PHONY: test-stress
test-stress:
	$(PYTEST) tests/stress -m stress $(SEQ_FLAGS) $(ARGS)

.PHONY: test-service
test-service:
	$(PYTEST) tests/service_testing $(SEQ_FLAGS) $(ARGS)

.PHONY: test-fuzz
test-fuzz:
	$(PYTEST) $(FUZZ_FLAGS) $(ARGS)

.PHONY: test-schema
test-schema:
	SCHEMA_QUICK=$(SCHEMA_QUICK) $(PYTEST) \
		tests/api/test_schemathesis.py \
		tests/api/test_schemathesis_agent.py \
		tests/api/test_schemathesis_swarm.py \
		tests/api/test_schemathesis_ttp.py \
		$(SCHEMA_FLAGS) $(ARGS)

.PHONY: test-bench
test-bench:
	$(PYTEST) tests/perf $(BENCH_FLAGS) $(ARGS)

.PHONY: test-docker
test-docker:
	DECNET_LIVE_DOCKER=1 $(PYTEST) tests/docker -m docker $(SEQ_FLAGS) $(ARGS)

# ── Static analysis ───────────────────────────────────────────────────────────

.PHONY: test-mypy
test-mypy:
	.311/bin/mypy decnet --ignore-missing-imports --no-error-summary

.PHONY: test-bandit
test-bandit:
	.311/bin/bandit -r decnet -c pyproject.toml

.PHONY: test-vulture
test-vulture:
	.311/bin/vulture decnet --min-confidence 80

.PHONY: test-pip-audit
test-pip-audit:
	.311/bin/pip-audit

# ── Composite: all suites ─────────────────────────────────────────────────────

_ALL_SUITES := core web db bus ttp intel analysis infra fleet cli features \
               go react \
               live api schema stress service fuzz bench docker \
               mypy bandit vulture pip-audit

.PHONY: test-all test
test-all test:
	@failed=""; \
	for suite in $(_ALL_SUITES); do \
		echo ""; \
		echo "══════════════════════════ $$suite ══════════════════════════"; \
		if $(MAKE) --no-print-directory test-$$suite ARGS="$(ARGS)"; then \
			echo "[PASS] $$suite"; \
		else \
			echo "[FAIL] $$suite"; \
			failed="$$failed $$suite"; \
			if [ "$(FAIL_FAST)" = "1" ]; then \
				echo "Stopping at first failure. Use FAIL_FAST=0 to run all suites."; \
				exit 1; \
			fi; \
		fi; \
	done; \
	if [ -n "$$failed" ]; then \
		echo ""; \
		echo "Failed:$$failed"; \
		exit 1; \
	fi; \
	echo ""; \
	echo "All suites passed."

.PHONY: help
help:
	@echo "Unit suites (xdist, 30s timeout):"
	@echo "  make test-core      tests/core + config + factories + fixtures"
	@echo "  make test-web       tests/web + services"
	@echo "  make test-db        tests/db + vectorstore"
	@echo "  make test-bus       tests/bus + logging + telemetry"
	@echo "  make test-ttp       tests/ttp"
	@echo "  make test-intel     tests/intel + asn + geoip"
	@echo "  make test-analysis  tests/clustering + correlation"
	@echo "  make test-infra     tests/agent + collector + sniffer + profiler"
	@echo "  make test-fleet     tests/fleet + swarm + topology + orchestrator + deploy + updater"
	@echo "  make test-cli       tests/cli + engine + mutator + realism"
	@echo "  make test-features  tests/canary + artifacts + webhook + decky_io + prober"
	@echo ""
	@echo "Go / React suites:"
	@echo "  make test-go        go test ./... in each Caddy module variant"
	@echo "  make test-react     vitest run in decnet_web"
	@echo ""
	@echo "Special suites (sequential, 120s timeout):"
	@echo "  make test-live      tests/live"
	@echo "  make test-api       tests/api  (schemathesis)"
	@echo "  make test-stress    tests/stress"
	@echo "  make test-service   tests/service_testing"
	@echo "  make test-schema              schemathesis contract tests (-m fuzz, xdist logical)"
	@echo "  make test-schema SCHEMA_QUICK=1   same, capped at 100 examples per test"
	@echo "  make test-fuzz      hypothesis fuzz (all normal dirs, -m fuzz, skips schemathesis files)"
	@echo "  make test-bench     tests/perf"
	@echo "  make test-docker    tests/docker  (needs DECNET_LIVE_DOCKER=1)"
	@echo ""
	@echo "Static analysis:"
	@echo "  make test-mypy      mypy type check on decnet/"
	@echo "  make test-bandit    bandit security scan on decnet/"
	@echo "  make test-vulture   vulture dead code scan (>=80% confidence)"
	@echo "  make test-pip-audit pip-audit dependency vulnerability scan"
	@echo ""
	@echo "Composites:"
	@echo "  make test-all       ALL suites (unit + go + react + live + api + schema + fuzz + bench + stress + docker + static analysis)"
	@echo "  make test-all FAIL_FAST=0   same, report all failures instead of stopping"
	@echo ""
	@echo "Passthrough: make test-web ARGS='--lf -s'"
