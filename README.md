# Immutable Audit Layer for IoT Safety Data in Construction Sites

**Laurea Magistrale - Politecnico di Torino**

---

## Architecture

```
IoT Simulators
    │  POST /events (JSON)
    ▼
Audit Gateway (FastAPI)
    │  validate → hash → store
    ▼
PostgreSQL (operational store)
  events table    - individual events + SHA-256 hashes
  batches table   - Merkle batch records
    │
    │  Every BATCH_WINDOW_SECONDS:
    │  1. Pull PENDING events
    │  2. Compute merkle_root = MerkleRoot(sorted event hashes)
    │  3. Compute meta_hash   = SHA256(canonical batch metadata)
    │  4. Call storeBatchRoot(batch_id, merkle_root, meta_hash)
    ▼
Hyperledger Besu (permissioned EVM)
  AuditAnchor.sol
    mapping(batchId → {merkleRoot, metaHash, blockTs, submitter})
    write-once: storeBatchRoot reverts if batchId already exists
    ▼
Verifier (independent)
  1. Fetch events from Postgres
  2. Recompute hashes + Merkle root
  3. Fetch root from Besu via getAnchor()
  4. Compare → PASS or FAIL + reason
```

**Why batching + Merkle?**

A common banca objection to blockchain audit layers is scalability. This design answers it directly: at 100 events/second with a 5-second window, the ledger sees 1 anchor transaction per 5 seconds (not 500). The Merkle tree provides the same tamper-evidence guarantee as storing all hashes individually, at O(log N) proof overhead.

**Why Besu (permissioned EVM) and not public Ethereum?**

- Zero gas fees (dev/QBFT network)
- Only `authorisedSubmitters` can call `storeBatchRoot` (RBAC in contract)
- No data leakage to public network
- Runs entirely in Docker - no token purchase, no external dependency
- Swap to Fabric by setting `LEDGER_BACKEND=fabric` and implementing `services/audit-gateway/app/ledger/fabric.py`

---

## Quick Start (WSL2 / Linux)

**Prerequisites:**
```bash
# Docker Desktop with WSL2 integration, or Docker Engine on Linux
docker --version   # 24+
docker compose version  # 2.x
```

**Start everything:**
```bash
git clone <repo>
cd iot-blockchain-poc
make up               # Postgres + Besu + Gateway (waits for healthy)
make deploy-contract  # Deploy AuditAnchor.sol (run once)
```

**Generate data:**
```bash
make seed     # 200 events at 1 eps for 200s
make stats    # event counts + batch status
```

**Run demo (thesis defense):**
```bash
make demo              # all 4 scenes (interactive)
make demo-fraud        # just the tamper detection scene
```

**Verify integrity:**
```bash
make verify            # all anchored batches → PASS/FAIL
make fraud-cases       # T1/T2/T3 fraud scenarios
```

**Run Chapter 5 experiments:**
```bash
make exp-all EPS=10 DURATION=120   # all experiments → results/
python scripts/collect_metrics.py  # print + CSV for LaTeX table
```

---

## Ports

| Service | Port | URL |
|---|---|---|
| Audit Gateway | 8000 | http://localhost:8000 |
| API docs | 8000 | http://localhost:8000/docs |
| PostgreSQL | 5432 | postgresql://audit:audit@localhost/auditdb |
| Besu JSON-RPC | 8545 | http://localhost:8545 |
| Besu WebSocket | 8546 | ws://localhost:8546 |

---

## Roles and Access Control

Pass `X-Role: <role>` header. In production, role is derived from client TLS certificate MSP attribute.

| Role | Submit | Read | Verify | Export |
|---|---|---|---|---|
| operator | ✓ | - | - | - |
| safety_manager | - | ✓ | - | - |
| inspector | - | ✓ | ✓ | ✓ |
| insurer | - | ✓ | ✓ | - |

---

## What is in the event hash?

Fields included in `SHA-256(canonical_json(event))`:

```
schema_version, event_type, ts, site_id, zone_id, actor_id, severity, source, payload
```

Fields **excluded** from the hash:
- `nonce` - used only for idempotent event ID generation
- `evidence_ref` - URI set asynchronously after submission

Any modification to any included field produces a different hash, detectable by the verifier.

---

## Threat Mitigations

| Threat | Mechanism |
|---|---|
| T1: Delete event from batch | Event hash absent from Merkle tree → verify FAIL |
| T2: Tamper event payload | SHA-256 mismatch → recomputed hash ≠ stored hash → FAIL |
| T3: Inject fake event | Injected hash changes Merkle root → anchor mismatch → FAIL |
| T4: Reorder events | Batch window bounds in `metaHash` are immutable on-chain |
| T5: Replay batch anchor | `storeBatchRoot` reverts on duplicate batchId (write-once) |
| T6: Unilateral ledger write | `authorisedSubmitters` RBAC in contract; extensible to multisig |

---

## Project Structure

```
iot-blockchain-poc/
├── docker-compose.yml
├── Makefile
├── README.md
├── contracts/
│   ├── AuditAnchor.sol       - write-once batch anchor (Solidity)
│   ├── deploy.py             - Python deployer (web3.py)
│   └── deployed.json         - address + ABI after deployment
├── services/
│   ├── audit-gateway/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── app/
│   │       ├── main.py       - FastAPI: ingest, batch, verify endpoints
│   │       ├── schemas.py    - Event schema (CANONICAL_FIELDS list)
│   │       ├── batching.py   - Batch window builder + anchor worker
│   │       ├── merkle.py     - Binary Merkle tree (canonical, sorted)
│   │       ├── db.py         - PostgreSQL DAL (events, batches)
│   │       ├── roles.py      - RBAC (operator/safety_manager/inspector/insurer)
│   │       └── ledger/
│   │           ├── adapter.py - Backend selector (stub/besu/fabric)
│   │           ├── besu.py    - Besu/web3.py implementation
│   │           └── fabric.py  - Fabric placeholder
│   ├── iot-sim/
│   │   ├── Dockerfile
│   │   └── sim.py            - 5 scenarios: normal/accident/near_miss/fraud/load
│   └── verifier/
│       ├── Dockerfile
│       └── verify.py         - T1/T2/T3 fraud cases + batch/event verify
├── scripts/
│   ├── demo.sh               - 4-scene thesis defense demo
│   ├── run_experiment.py     - E1–E6 experiments → CSV
│   └── collect_metrics.py    - Aggregate CSVs → Chapter 5 table
├── docs/
│   ├── architecture.md
│   ├── audit-event-contract.md
│   ├── threat-model.md
│   └── ...
└── results/
    └── E5_20241115_143022/
        ├── events.csv
        ├── metrics.csv
        └── report.json
```

---

## Chapter 5 Experiments

| Exp | Name | What it measures |
|---|---|---|
| E1 | Functional Correctness | All fields stored correctly, idempotency |
| E2 | Tamper Detection | 20 PASS + 20 FAIL detection rate |
| E3 | Batch Integrity | Merkle root matches Besu anchor |
| E4 | Incident End-to-End | 7-event chain queryability |
| E5 | Throughput | p50/p95/p99 at configurable EPS |
| E6 | Fraud Verification | T1/T2/T3 detection via Merkle proof |

```bash
make exp-all EPS=10 DURATION=120
python scripts/collect_metrics.py
# Prints and saves results/chapter5_table.csv
```

---

## Notes on Configuration

All claimed performance numbers in the thesis should reference the experiment output in `results/` and be labelled:

> "Measured in simulated environment (Docker on WSL2). Real-network performance subject to validator count, block time, and network latency."

This is standard practice and pre-empts the "you measured this in simulation" objection.
