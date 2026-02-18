GATEWAY_URL ?= http://localhost:8080

.PHONY: help up-stub up-docker up-fabric down install-dev \
        seed demo-tamper demo-incident query-stats \
        export-report export-zone-Z04 export-actor-W001 \
        verify-report clean

help:
	@echo "Immutable Audit Layer"
	@echo ""
	@echo "  make up-stub           Start gateway in stub mode (no Docker)"
	@echo "  make up-docker         Start full stack via Docker Compose"
	@echo "  make up-fabric         Start Fabric network + deploy chaincode + start gateway"
	@echo "  make down              Stop all services"
	@echo ""
	@echo "  make install-dev       Install Python dependencies"
	@echo "  make seed              Seed ledger with demo data"
	@echo ""
	@echo "  make demo-tamper       Run tamper detection demo"
	@echo "  make demo-incident     Load incident day scenario"
	@echo ""
	@echo "  make query-stats       Show ledger statistics"
	@echo "  make export-report     Export full audit report"
	@echo "  make verify-report     Batch verify exported report"
	@echo ""
	@echo "  make clean             Remove generated files"

install-dev:
	pip install -r gateway/requirements.txt requests

up-stub:
	bash scripts/up.sh --stub

up-docker:
	bash scripts/up.sh --docker

up-fabric:
	bash scripts/up.sh --fabric

down:
	bash scripts/down.sh

seed:
	bash scripts/seed.sh

demo-tamper:
	cd simulator && python3 generate_events.py --tamper-demo --gateway $(GATEWAY_URL)

demo-incident:
	cd simulator && python3 generate_events.py \
		--scenario scenarios/incident_day.json \
		--gateway $(GATEWAY_URL)

query-stats:
	@curl -s $(GATEWAY_URL)/stats | python3 -m json.tool

query-zone-Z04:
	@curl -s "$(GATEWAY_URL)/events?zone_id=Z04" | python3 -m json.tool

query-critical:
	@curl -s "$(GATEWAY_URL)/events?severity=critical" | python3 -m json.tool

query-near-miss:
	@curl -s "$(GATEWAY_URL)/events?event_type=NEAR_MISS" | python3 -m json.tool

export-report:
	bash scripts/export_audit_report.sh

export-zone-Z04:
	bash scripts/export_audit_report.sh --zone Z04

export-actor-W001:
	bash scripts/export_audit_report.sh --actor W001

verify-report:
	@REPORT=$$(ls results/audit_report_*.json 2>/dev/null | head -1); \
	if [ -z "$$REPORT" ]; then echo "No report found. Run 'make export-report' first."; exit 1; fi; \
	python3 scripts/verify_integrity.py --report $$REPORT --gateway $(GATEWAY_URL)

clean:
	find results/ -name "*.json" -not -name "sample_report.json" -delete 2>/dev/null || true
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
