GATEWAY_URL ?= http://localhost:8080

.PHONY: help install-dev test lint \
        fabric-up fabric-deploy fabric-down fabric-reset \
        up-stub up-docker up-fabric down dashboard \
        seed demo demo-scene1 demo-scene2 demo-scene3 \
        sim-normal sim-accident sim-near-miss sim-fraud sim-replay sim-rate \
        exp-e1 exp-e2 exp-e3 exp-e4 exp-e5 exp-e6 exp-all \
        query-stats export-report verify-report metrics-export clean

help:
	@echo "Immutable Audit Layer - Politecnico di Torino"
	@echo ""
	@echo "Fabric network"
	@echo "  make fabric-up       Generate crypto + start Fabric containers"
	@echo "  make fabric-deploy   Install and commit auditcc chaincode"
	@echo "  make fabric-down     Stop network + remove volumes"
	@echo "  make fabric-reset    Clean restart"
	@echo ""
	@echo "Application stack"
	@echo "  make up-stub         Gateway in stub mode (no Docker - fastest)"
	@echo "  make up-docker       Gateway + MinIO via Docker Compose"
	@echo "  make up-fabric       Gateway connected to real Fabric network"
	@echo "  make down            Stop application stack"
	@echo "  make dashboard       Streamlit dashboard at http://localhost:8501"
	@echo ""
	@echo "Demo (thesis defense)"
	@echo "  make demo            Run all 3 scripted scenes (interactive)"
	@echo "  make demo-scene1     Scene 1: normal monitoring"
	@echo "  make demo-scene2     Scene 2: near-miss escalation chain"
	@echo "  make demo-scene3     Scene 3: tamper detection"
	@echo ""
	@echo "Experiments (Chapter 5)"
	@echo "  make exp-e1          E1: Functional correctness (50 events)"
	@echo "  make exp-e2          E2: Tamper detection (20 + 20 payloads)"
	@echo "  make exp-e3          E3: Query correctness (100 events)"
	@echo "  make exp-e4          E4: Incident end-to-end (7-event chain)"
	@echo "  make exp-e5          E5: Throughput (10 tx/s, 120s)"
	@echo "  make exp-e6          E6: Batch integrity verification (50 events)"
	@echo "  make exp-all         Run E1–E6, write summary to results/"
	@echo ""
	@echo "Simulation (data generation)"
	@echo "  make seed            Accident + near-miss + 200 normal events"
	@echo "  make sim-normal      200 random operational events"
	@echo "  make sim-accident    Causal chain: entry -> PPE violation -> fall"
	@echo "  make sim-near-miss   Near-miss escalation chain"
	@echo "  make sim-fraud       Tamper detection demo (CLI version)"
	@echo "  make sim-replay      Replay attack / idempotency demo"
	@echo "  make sim-rate        Rate-based throughput: 10 tx/s for 60s"
	@echo ""
	@echo "Audit and reports"
	@echo "  make query-stats     Event counts by type, severity, zone"
	@echo "  make export-report   Export audit report to results/"
	@echo "  make verify-report   Batch verify exported report"
	@echo "  make metrics-export  Export metrics CSV for current session"
	@echo ""
	@echo "Setup and tests"
	@echo "  make install-dev     Install Python dependencies"
	@echo "  make test            Run unit tests"
	@echo "  make lint            Lint gateway and simulator"
	@echo "  make clean           Remove generated results files"

install-dev:
	pip install -r gateway/requirements.txt requests pytest
	pip install -r dashboard/requirements.txt

test:
	python3 -m pytest tests/ -v

lint:
	python3 -m pyflakes gateway/app/ simulator/ scripts/ experiments/ 2>/dev/null || true

# Fabric network lifecycle
fabric-up:
	bash fabric/network/network.sh up

fabric-deploy:
	bash fabric/network/network.sh deploy

fabric-down:
	bash fabric/network/network.sh down

fabric-reset:
	bash fabric/network/network.sh reset

# Application stack
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

# Demo scenes
demo:
	bash scripts/demo.sh all

demo-scene1:
	bash scripts/demo.sh 1

demo-scene2:
	bash scripts/demo.sh 2

demo-scene3:
	bash scripts/demo.sh 3

# Experiments
exp-e1:
	python3 experiments/run_experiment.py --experiment E1 --gateway $(GATEWAY_URL)

exp-e2:
	python3 experiments/run_experiment.py --experiment E2 --gateway $(GATEWAY_URL)

exp-e3:
	python3 experiments/run_experiment.py --experiment E3 --gateway $(GATEWAY_URL)

exp-e4:
	python3 experiments/run_experiment.py --experiment E4 --gateway $(GATEWAY_URL)

exp-e5:
	python3 experiments/run_experiment.py --experiment E5 --gateway $(GATEWAY_URL) \
		--rate 10 --duration 120

exp-e6:
	python3 experiments/run_experiment.py --experiment E6 --gateway $(GATEWAY_URL)

exp-all:
	python3 experiments/run_experiment.py --experiment all --gateway $(GATEWAY_URL)

# Simulation scenarios
sim-normal:
	cd simulator && python3 generate_events.py --scenario normal --count 200 \
		--gateway $(GATEWAY_URL)

sim-accident:
	cd simulator && python3 generate_events.py --scenario accident \
		--gateway $(GATEWAY_URL)

sim-near-miss:
	cd simulator && python3 generate_events.py --scenario near_miss \
		--gateway $(GATEWAY_URL)

sim-fraud:
	cd simulator && python3 generate_events.py --scenario fraud \
		--gateway $(GATEWAY_URL)

sim-replay:
	cd simulator && python3 generate_events.py --scenario replay \
		--gateway $(GATEWAY_URL)

sim-rate:
	cd simulator && python3 generate_events.py --rate 10 --duration 60 \
		--export --gateway $(GATEWAY_URL)

# Audit and reports
query-stats:
	@curl -s -H "X-Role: safety_manager" $(GATEWAY_URL)/stats | python3 -m json.tool

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
