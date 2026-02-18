GATEWAY_URL ?= http://localhost:8080

.PHONY: help install-dev test lint \
        up-stub up-docker up-fabric down \
        seed \
        sim-normal sim-accident sim-near-miss sim-fraud sim-replay sim-rate \
        dashboard \
        query-stats export-report verify-report \
        metrics-export clean

help:
	@echo "Immutable Audit Layer — Makefile"
	@echo ""
	@echo "Setup"
	@echo "  make install-dev          Install Python dependencies (gateway + dashboard)"
	@echo "  make test                 Run unit tests"
	@echo "  make lint                 Run pyflakes on gateway and simulator"
	@echo ""
	@echo "Start / Stop"
	@echo "  make up-stub              Start gateway in stub mode (no Docker)"
	@echo "  make up-docker            Start gateway + MinIO via Docker Compose"
	@echo "  make up-fabric            Start Fabric network + deploy chaincode"
	@echo "  make down                 Stop all services"
	@echo "  make dashboard            Start Streamlit dashboard"
	@echo ""
	@echo "Simulation scenarios"
	@echo "  make seed                 Load incident scenario + 200 normal events"
	@echo "  make sim-normal           200 random operational events"
	@echo "  make sim-accident         Accident chain: entry -> PPE violation -> fall"
	@echo "  make sim-near-miss        Near-miss escalation chain"
	@echo "  make sim-fraud            Tamper detection demo"
	@echo "  make sim-replay           Replay attack / idempotency demo"
	@echo "  make sim-rate             Rate-based throughput simulation (10 tx/s, 60s)"
	@echo ""
	@echo "Queries and reports"
	@echo "  make query-stats          Event counts by type, severity, zone"
	@echo "  make export-report        Export full audit report to results/"
	@echo "  make verify-report        Batch verify integrity of exported report"
	@echo "  make metrics-export       Export metrics CSV for current session"
	@echo ""
	@echo "  make clean                Remove generated files"

install-dev:
	pip install -r gateway/requirements.txt requests pytest
	pip install -r dashboard/requirements.txt

test:
	python3 -m pytest tests/ -v

lint:
	python3 -m pyflakes gateway/app/ simulator/ scripts/ 2>/dev/null || true

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
	cd simulator && python3 generate_events.py --rate 10 --duration 60 --gateway $(GATEWAY_URL)

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
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
