# Immutable Audit Layer — Makefile
# All commands run from repo root in WSL or Linux.
# Requires: Docker Desktop with WSL2 integration enabled.

GATEWAY     ?= http://localhost:8000
LEDGER      ?= besu
BATCH_SECS  ?= 5
EPS         ?= 10
DURATION    ?= 120

.PHONY: help up down build logs seed load \
        verify verify-batch verify-event fraud-cases \
        deploy-contract \
        exp-e1 exp-e2 exp-e3 exp-e4 exp-e5 exp-e6 exp-all \
        demo demo-accident demo-near-miss demo-fraud demo-monitor \
        stats clean

help:
	@echo "Immutable Audit Layer — Politecnico di Torino"
	@echo ""
	@echo "Stack"
	@echo "  make up              Start all containers (Postgres + Besu + Gateway)"
	@echo "  make down            Stop and remove containers"
	@echo "  make build           Rebuild images"
	@echo "  make logs            Follow gateway + besu logs"
	@echo "  make deploy-contract Deploy AuditAnchor.sol to Besu"
	@echo ""
	@echo "Data"
	@echo "  make seed            Seed EPS=$(EPS) for $(DURATION)s"
	@echo "  make load            Load test: EPS=$(EPS) for $(DURATION)s"
	@echo "  make stats           Show event counts and batch status"
	@echo ""
	@echo "Verification"
	@echo "  make verify              Verify all anchored batches"
	@echo "  make verify-batch ID=... Verify specific batch"
	@echo "  make verify-event ID=... Verify specific event"
	@echo "  make fraud-cases         Run T1/T2/T3 fraud detection scenarios"
	@echo ""
	@echo "Experiments (Chapter 5)"
	@echo "  make exp-e1    Functional correctness (48 events)"
	@echo "  make exp-e2    Tamper detection (20 + 20)"
	@echo "  make exp-e3    Batch integrity (Merkle + ledger)"
	@echo "  make exp-e4    Incident end-to-end (7-event chain)"
	@echo "  make exp-e5    Throughput: EPS=$(EPS) for $(DURATION)s"
	@echo "  make exp-e6    Fraud verification (T1/T2/T3)"
	@echo "  make exp-all   Run E1–E6 → results/summary_*.json"
	@echo ""
	@echo "Demo (thesis defense)"
	@echo "  make demo              All 4 demo scenes (interactive)"
	@echo "  make demo-accident     Scene: entry → PPE violation → fall"
	@echo "  make demo-near-miss    Scene: escalating near-miss chain"
	@echo "  make demo-fraud        Scene: tamper detection (T2)"
	@echo "  make demo-monitor      Scene: normal monitoring"
	@echo ""
	@echo "  make clean   Remove result files"

#  Stack lifecycle 

up:
	@echo "Starting stack (Postgres + Besu + Gateway)..."
	LEDGER_BACKEND=$(LEDGER) BATCH_WINDOW_SECONDS=$(BATCH_SECS) \
	  docker compose up -d postgres besu audit-gateway
	@echo "Waiting for gateway..."
	@until curl -sf $(GATEWAY)/health > /dev/null 2>&1; do sleep 2; printf '.'; done; echo
	@echo "Stack ready: $(GATEWAY)"
	@echo "API docs:   $(GATEWAY)/docs"

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f audit-gateway besu

deploy-contract:
	@echo "Deploying AuditAnchor.sol to Besu..."
	docker compose run --rm contract-deployer
	@echo "Contract deployed. Address saved to contracts/deployed.json."

#  Data generation 

seed:
	docker compose run --rm \
	  -e GATEWAY_URL=http://audit-gateway:8000 \
	  --entrypoint python \
	  iot-sim sim.py --scenario normal --eps $(EPS) --duration $(DURATION) \
	    --gateway http://audit-gateway:8000

load:
	docker compose run --rm \
	  -e GATEWAY_URL=http://audit-gateway:8000 \
	  --entrypoint python \
	  iot-sim sim.py --scenario load --eps $(EPS) --duration $(DURATION) \
	    --gateway http://audit-gateway:8000

stats:
	@curl -sf -H "X-Role: safety_manager" $(GATEWAY)/stats | python3 -m json.tool
	@echo ""
	@curl -sf -H "X-Role: inspector" $(GATEWAY)/batches | python3 -c \
	  "import sys,json; b=json.load(sys.stdin); \
	   print(f'Batches: {len(b)} total, {sum(1 for x in b if x[\"anchor_status\"]==\"ANCHORED\")} anchored')"

#  Verification 

verify:
	@echo "Verifying all anchored batches..."
	docker compose run --rm \
	  -e GATEWAY_URL=http://audit-gateway:8000 \
	  verifier all-batches --gateway http://audit-gateway:8000 --out /app/results

verify-batch:
	@test -n "$(ID)" || (echo "Usage: make verify-batch ID=<batch_id>"; exit 1)
	docker compose run --rm verifier batch $(ID) --gateway http://audit-gateway:8000

verify-event:
	@test -n "$(ID)" || (echo "Usage: make verify-event ID=<event_id>"; exit 1)
	docker compose run --rm verifier event $(ID) --gateway http://audit-gateway:8000

fraud-cases:
	@echo "Running fraud detection scenarios T1/T2/T3..."
	docker compose run --rm \
	  verifier fraud-cases --gateway http://audit-gateway:8000 --out /app/results

#  Experiments 

exp-e1:
	python3 scripts/run_experiment.py --exp E1 --gateway $(GATEWAY)

exp-e2:
	python3 scripts/run_experiment.py --exp E2 --gateway $(GATEWAY)

exp-e3:
	python3 scripts/run_experiment.py --exp E3 --gateway $(GATEWAY)

exp-e4:
	python3 scripts/run_experiment.py --exp E4 --gateway $(GATEWAY)

exp-e5:
	python3 scripts/run_experiment.py --exp E5 \
	  --eps $(EPS) --duration $(DURATION) --gateway $(GATEWAY)

exp-e6:
	python3 scripts/run_experiment.py --exp E6 --gateway $(GATEWAY)

exp-all:
	python3 scripts/run_experiment.py --exp all \
	  --eps $(EPS) --duration $(DURATION) --gateway $(GATEWAY)
	@echo "Results in results/"

#  Demo scenes 

demo:
	@bash scripts/demo.sh all

demo-accident:
	@bash scripts/demo.sh accident

demo-near-miss:
	@bash scripts/demo.sh near_miss

demo-fraud:
	@bash scripts/demo.sh fraud

demo-monitor:
	@bash scripts/demo.sh monitor

#  Utilities 

clean:
	find results/ -name "*.json" -name "*.csv" -delete 2>/dev/null || true
	find results/ -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
