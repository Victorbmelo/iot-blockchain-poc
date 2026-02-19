# Immutable Audit Layer for IoT Safety Data in Construction Sites

**Laurea Magistrale - Politecnico di Torino**

---

## Architecture

```
IoT Simulators
    |  POST /events (JSON)
    v
Audit Gateway (FastAPI)
    |  validate -> hash -> store
    v
PostgreSQL (operational store)
  events table    - individual events + SHA-256 hashes
  batches table   - Merkle batch records
    |
    |  Every BATCH_WINDOW_SECONDS:
    |  1. Pull PENDING events
    |  2. Compute merkle_root = MerkleRoot(sorted event hashes)
    |  3. Compute meta_hash   = SHA256(canonical batch metadata)
    |  4. Call storeBatchRoot(batch_id, merkle_root, meta_hash)
    v
Hyperledger Besu (permissioned EVM)
  AuditAnchor.sol
    mapping(batchId -> {merkleRoot, metaHash, blockTs, submitter})
    write-once: storeBatchRoot reverts if batchId already exists
    v
Verifier (independent)
  1. Fetch events from Postgres
  2. Recompute hashes + Merkle root
  3. Fetch root from Besu via getAnchor()
  4. Compare -> PASS or FAIL + reason
```

---

## Why batching + Merkle?

At 100 events/second with a 5-second window, the ledger sees **1 transaction per 5 seconds**, not 500.

The Merkle tree preserves tamper-evidence with:

* O(log N) proof size
* Constant on-chain storage
* Linear off-chain scalability

This directly answers scalability objections from academic committees.

---

## Why Besu (permissioned EVM)?

* No public gas costs
* Controlled validators
* RBAC enforced in smart contract
* Fully local reproducibility
* Swappable backend (`LEDGER_BACKEND=fabric`)

---

# Quick Start (WSL2 / Linux)

## Prerequisites

```bash
docker --version      # 24+
docker compose version
make --version
```

---

## First Time Setup

```bash
git clone <repo>
cd iot-blockchain-poc
make up
make deploy-contract
```

! If you ever run:

```bash
docker compose down -v
```

You MUST re-run:

```bash
make deploy-contract
```

because the blockchain state was erased.

---

# Full Reset (Hard Clean Rebuild)

Use this if:

* Code changes are not reflected
* Python container still runs old code
* Weird Docker caching issues
* Besu behaving inconsistently

```bash
docker compose down -v --remove-orphans
docker image rm -f \
  iot-blockchain-poc-iot-sim \
  iot-blockchain-poc-audit-gateway \
  iot-blockchain-poc-contract-deployer 2>/dev/null || true
docker builder prune -af
```

Then:

```bash
make up
make deploy-contract
```

This guarantees:

* Fresh volumes
* Fresh images
* No stale layers
* No cached sim.py
* Clean chain state


**or**


# Soft Reset

```bash
# Full reset (clean state)
docker compose down -v
docker system prune -f

# Rebuild images after code changes
docker compose build --no-cache audit-gateway verifier iot-sim

# Start stack
make up
make deploy-contract

# Generate events + wait batch window
make seed
sleep 8

# Inspect + verify
make stats
make verify
```

---

# Normal Workflow

## Generate data

```bash
make seed
make stats
```

## Verify integrity

```bash
make verify
make fraud-cases
```

## Demo (thesis defense)

```bash
make demo
make demo-fraud
```

---

# Chapter 5 Experiments

```bash
make exp-all EPS=10 DURATION=120
python scripts/collect_metrics.py
```

Outputs:

```
results/<timestamp>/
  events.csv
  metrics.csv
  report.json
```

Use:

```
results/chapter5_table.csv
```

for LaTeX tables.

---

# Ports

| Service       | Port | URL                                                      |
| ------------- | ---- | -------------------------------------------------------- |
| Audit Gateway | 8000 | [http://localhost:8000](http://localhost:8000)           |
| API Docs      | 8000 | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Demo UI       | 8000 | [http://localhost:8000/ui](http://localhost:8000/ui)     |
| PostgreSQL    | 5432 | postgresql://audit:audit@localhost/auditdb               |
| Besu RPC      | 8545 | [http://localhost:8545](http://localhost:8545)           |

---

# Common Errors & Fixes

---

## 1) Besu container unhealthy

Cause: healthcheck using curl but curl not installed.

Fix: use process-based healthcheck in docker-compose.

---

## 2) Contract deploy fails with:

```
AttributeError: raw_transaction
```

Fix in deploy.py:

```python
raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
tx_hash = w3.eth.send_raw_transaction(raw)
```

---

## 3) Account balance = 0 ETH

Expected in local Besu if genesis has no alloc.

For development network, zero gas is acceptable.

If using gas > 0, add alloc in genesis.

---

## 4) sim.py SyntaxError (global GATEWAY)

Ensure:

```python
def main():
    global GATEWAY
```

appears BEFORE using GATEWAY.

Then rebuild:

```bash
docker compose build --no-cache iot-sim
```

---

## 5) Code changes not reflected

Docker cached old image.

Run:

```bash
docker builder prune -af
docker compose build --no-cache
```

---

# Roles and Access Control

Header:

```
X-Role: operator | safety_manager | inspector | insurer
```

In production:

* Role derived from client TLS certificate.

---

# Threat Mitigations

| Threat                 | Mechanism            |
| ---------------------- | -------------------- |
| T1: Delete event       | Merkle root mismatch |
| T2: Tamper payload     | SHA-256 mismatch     |
| T3: Inject fake event  | Anchor mismatch      |
| T4: Reorder events     | metaHash immutable   |
| T5: Replay anchor      | write-once mapping   |
| T6: Unauthorized write | RBAC in contract     |

---

# Reproducibility Note

All measurements must state:
> Measured in Docker-based simulated environment (WSL2). Real-world performance depends on validator count, block time, and network latency.
