GATEWAY_URL ?= http://localhost:8080

.PHONY: help install-dev test lint \
        fabric-up fabric-deploy fabric-down fabric-reset \
        up-stub up-docker up-fabric down \
        dashboard seed \
        sim-normal sim-accident sim-near-miss sim-fraud sim-replay sim-rate \
        query-stats export-report verify-report metrics-export clean

help:
	@echo "Immutable Audit Layer"
	@echo ""
	@echo "Fabric network (requires Fabric binaries on PATH)"
	@echo "  make fabric-up        Generate crypto + start Fabric containers"
	@echo "  make fabric-deploy    Package, install, commit auditcc chaincode"
	@echo "  make fabric-down      Stop Fabric network + remove volumes"
	@echo "  make fabric-reset     fabric-down + fabric-up"
	@echo ""
	@echo "Application stack"
	@echo "  make up-stub          Gateway in stub mode (no Docker, no Fabric)"
	@echo "  make up-docker        Gateway + MinIO via Docker Compose (stub)"
	@echo "  make up-fabric        Gateway connected to real Fabric network"
	@echo "  make down             Stop application stack"
	@echo "  make dashboard        Start Streamlit dashboard"
	@echo ""
	@echo "Setup and tests"
	@echo "  make install-dev      Install Python dependencies"
	@echo "  make test             Run unit tests"
	@echo "  make lint             Lint gateway and simulator code"
	@echo ""
	@echo "Simulation scenarios"
	@echo "  make seed             Load accident + near-miss + 200 normal events"
	@echo "  make sim-normal       200 random operational events"
	@echo "  make sim-accident     Causal chain: entry -> PPE violation -> fall"
	@echo "  make sim-near-miss    Escalating near-miss chain"
	@echo "  make sim-fraud        Tamper detection demo"
	@echo "  make sim-replay       Idempotency / replay attack demo"
	@echo "  make sim-rate         Throughput: 10 tx/s for 60s (E7 experiment)"
	@echo ""
	@echo "Reports and audit"
	@echo "  make query-stats      Event counts by type, severity, zone"
	@echo "  make export-report    Export audit report to results/"
	@echo "  make verify-report    Batch verify exported report"
	@echo "  make metrics-export   Export metrics CSV for current session"
	@echo ""
	@echo "  make clean            Remove generated files"

install-dev:
	pip install -r gateway/requirements.txt requests pytest
	pip install -r dashboard/requirements.txt

test:
	python3 -m pytest tests/ -v

lint:
	python3 -m pyflakes gateway/app/ simulator/ scripts/ 2>/dev/null || true

fabric-up:
	bash fabric/network/network.sh up

fabric-deploy:
	bash fabric/network/network.sh deploy

fabric-down:
	bash fabric/network/network.sh down

fabric-reset:
	bash fabric/network/network.sh reset

up-stub:
	bash scripts/up.sh --stub

up-docker:
	bash scripts/up.sh --docker

up-fabric:
	bash scripts/up.sh --fabric

down:
	bash scripts/down.sh

dashboard:
	streamlit run dashboard/app.py

seed:
	bash scripts/seed.sh

sim-normal:
	cd simulator && python3 generate_events.py --scenario normal --count 200 --gateway $(GATEWAY_URL)

sim-accident:
	cd simulator && python3 generate_events.py --scenario accident --gateway $(GATEWAY_URL)

sim-near-miss:
	cd simulator && python3 generate_events.py --scenario near_miss --gateway $(GATEWAY_URL)

sim-fraud:
	cd simulator && python3 generate_events.py --scenario fraud --gateway $(GATEWAY_URL)

sim-replay:
	cd simulator && python3 generate_events.py --scenario replay --gateway $(GATEWAY_URL)

sim-rate:
	cd simulator && python3 generate_events.py --rate 10 --duration 60 --export --gateway $(GATEWAY_URL)

query-stats:
	@curl -s $(GATEWAY_URL)/stats | python3 -m json.tool

export-report:
	bash scripts/export_audit_report.sh

verify-report:
	@REPORT=$$(ls results/audit_report_*.json 2>/dev/null | head -1); \
	if [ -z "$$REPORT" ]; then echo "No report found. Run 'make export-report' first."; exit 1; fi; \
	python3 scripts/verify_integrity.py --report $$REPORT --gateway $(GATEWAY_URL)

metrics-export:
	@curl -s -X POST $(GATEWAY_URL)/metrics/export | python3 -m json.tool

clean:
	find results/ -name "*.json" -not -name "sample_report.json" -delete 2>/dev/null || true
	find results/ -name "*.csv" -delete 2>/dev/null || true
	find results/ -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
