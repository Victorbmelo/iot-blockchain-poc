"""
main.py - Audit Gateway REST API.

Architecture position: this process sits between the IoT simulators and the ledger.
  IoT → POST /events → validate → store in Postgres → batch worker → anchor on Besu

Role enforcement: all mutating endpoints require OPERATOR role.
All read/verify endpoints require INSPECTOR or INSURER.
"""
import asyncio
import logging
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .db import (
    get_batch, get_batch_events, get_batches, get_event, get_events,
    get_stats, init_db, insert_event,
)
from .batching import batch_worker, _close_batch
from .schemas import BatchOut, EventIn, EventOut, SCHEMA_VERSION, VerifyResult
from .roles import Role, PERMISSIONS, require, get_role, resolve_role
from .ledger.adapter import BACKEND, get_anchor

log = logging.getLogger("audit.gateway")

app = FastAPI(
    title="Audit Gateway",
    description=(
        "Immutable audit layer for construction site safety data.\n\n"
        "**Flow**: IoT events → Postgres → Merkle batch → Besu anchor\n\n"
        "**Roles** (X-Role header): `operator` | `safety_manager` | `inspector` | `insurer`\n\n"
        "Thesis: *Immutable Audit Layer for IoT Safety Data* - Politecnico di Torino"
    ),
    version=SCHEMA_VERSION,
)

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

#  Startup / Shutdown 

@app.on_event("startup")
async def startup():
    import asyncpg
    # Wait for Postgres to be ready
    for attempt in range(30):
        try:
            await init_db()
            break
        except Exception:
            await asyncio.sleep(2)
    else:
        log.error("Postgres not available after 60s")
        raise RuntimeError("Database unavailable")

    asyncio.create_task(batch_worker())
    log.info("Audit Gateway started - backend=%s schema=%s", BACKEND, SCHEMA_VERSION)


@app.on_event("shutdown")
async def shutdown():
    from .db import close_pool
    await close_pool()


#  System endpoints 

@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "schema_version": SCHEMA_VERSION,
        "ledger_backend": BACKEND,
        "batch_window_s": int(os.getenv("BATCH_WINDOW_SECONDS", "5")),
    }


@app.get("/roles", tags=["system"])
async def list_roles():
    return {r.value: sorted(p) for r, p in PERMISSIONS.items()}


@app.get("/stats", tags=["system"],
         dependencies=[Depends(require("read_stats"))])
async def stats():
    return await get_stats()


#  Event ingestion - OPERATOR only 

@app.post("/events", tags=["events"], status_code=201)
async def submit_event(
    body: EventIn,
    role: Role = Depends(require("submit_event")),
):
    """Validate, hash, and store a safety event. Batch worker anchors it to Besu.

    What goes into the hash:
      schema_version, event_type, ts, site_id, zone_id, actor_id, severity, source, payload

    What is excluded from the hash:
      nonce (idempotency key, not payload), evidence_ref (set asynchronously)
    """
    t0 = time.monotonic()
    event = body.model_dump()
    stored = await insert_event(event)
    latency_ms = round((time.monotonic() - t0) * 1000, 2)
    log.info("event stored id=%s type=%s zone=%s latency_ms=%.1f",
             stored["event_id"], stored["event_type"], stored["zone_id"], latency_ms)
    return {**stored, "_latency_ms": latency_ms}


#  Event queries 

@app.get("/events", tags=["events"],
         dependencies=[Depends(require("read_events"))])
async def list_events(
    actor_id:    Optional[str] = Query(None),
    zone_id:     Optional[str] = Query(None),
    event_type:  Optional[str] = Query(None),
    severity_min: int          = Query(0, ge=0, le=5),
    limit:       int           = Query(50, ge=1, le=500),
    offset:      int           = Query(0, ge=0),
):
    return await get_events(actor_id, zone_id, event_type, severity_min, limit, offset)


@app.get("/events/{event_id}", tags=["events"],
         dependencies=[Depends(require("read_events"))])
async def get_event_by_id(event_id: str):
    ev = await get_event(event_id)
    if not ev:
        raise HTTPException(404, detail=f"Event {event_id} not found")
    return ev


#  Batch queries 

@app.get("/batches", tags=["batches"],
         dependencies=[Depends(require("read_batches"))])
async def list_batches(
    limit:  int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    return await get_batches(limit, offset)


@app.get("/batches/{batch_id}", tags=["batches"],
         dependencies=[Depends(require("read_batches"))])
async def get_batch_by_id(batch_id: str):
    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(404, detail=f"Batch {batch_id} not found")
    # Enrich with on-chain anchor data
    anchor = await get_anchor(batch_id)
    return {**batch, "ledger_anchor": anchor}


@app.get("/batches/{batch_id}/events", tags=["batches"],
         dependencies=[Depends(require("read_batches"))])
async def get_events_in_batch(batch_id: str):
    return await get_batch_events(batch_id)


#  Force batch close (for experiments and demo) 

@app.post("/batches/close", tags=["batches"], status_code=202,
          dependencies=[Depends(require("submit_event"))])
async def force_close_batch():
    """Force immediate batch close without waiting for the timer.
    Used in experiments to control timing precisely.
    """
    await _close_batch()
    return {"status": "batch closed"}


#  Integrity verification 

@app.get("/verify/batch/{batch_id}", tags=["integrity"],
         response_model=VerifyResult,
         dependencies=[Depends(require("verify_batch"))])
async def verify_batch(batch_id: str):
    """Full batch integrity verification.

    Algorithm:
    1. Load all events for this batch from Postgres
    2. Recompute SHA-256 hash for each event from stored payload
    3. Rebuild Merkle root from event hashes
    4. Read merkle_root from the ledger (Besu getAnchor)
    5. Compare: if equal → PASS, else FAIL

    This answers: "have any events been modified, added, or removed since anchoring?"
    """
    from .merkle import compute_root
    from .db import compute_event_hash

    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(404, detail=f"Batch {batch_id} not found")

    if batch["anchor_status"] != "ANCHORED":
        return VerifyResult(
            verdict="PENDING",
            reason=f"Batch {batch_id} has not been anchored yet (status={batch['anchor_status']})",
            batch_id=batch_id,
        )

    events = await get_batch_events(batch_id)
    if not events:
        return VerifyResult(verdict="FAIL", reason="No events found for batch", batch_id=batch_id)

    # Recompute hashes and Merkle root
    events_ok, events_tampered = 0, 0
    event_hashes = []
    for ev in events:
        recomputed = compute_event_hash(ev)
        if recomputed == ev["event_hash"]:
            events_ok += 1
            event_hashes.append(recomputed)
        else:
            events_tampered += 1
            log.warning("tampered event detected: id=%s stored=%s computed=%s",
                        ev["event_id"], ev["event_hash"][:16], recomputed[:16])

    computed_root = compute_root(event_hashes)

    # Read from ledger
    anchor = await get_anchor(batch_id)
    ledger_root = anchor["merkle_root"] if anchor else None
    roots_match = computed_root == ledger_root if ledger_root else False

    if events_tampered > 0:
        verdict = "FAIL"
        reason = f"{events_tampered} event(s) have been tampered - hash mismatch in PostgreSQL"
    elif not ledger_root:
        verdict = "FAIL"
        reason = "Batch not found on ledger - possible deletion attack"
    elif not roots_match:
        verdict = "FAIL"
        reason = (f"Merkle root mismatch: computed={computed_root[:16]}... "
                  f"on-chain={ledger_root[:16]}...")
    else:
        verdict = "PASS"
        reason = (f"All {events_ok} event hashes verified. "
                  f"Merkle root matches on-chain anchor.")

    return VerifyResult(
        verdict=verdict, reason=reason, batch_id=batch_id,
        event_count=len(events), events_ok=events_ok, events_tampered=events_tampered,
        events_missing=0,
        merkle_root_computed=computed_root,
        merkle_root_on_chain=ledger_root,
        roots_match=roots_match,
    )


@app.post("/verify/event/{event_id}", tags=["integrity"],
          dependencies=[Depends(require("verify_event"))])
async def verify_event(event_id: str):
    """Verify a single event: recompute hash and check Merkle proof against anchored root."""
    from .merkle import compute_root, compute_proof, verify_proof
    from .db import compute_event_hash

    ev = await get_event(event_id)
    if not ev:
        raise HTTPException(404, detail=f"Event {event_id} not found")

    recomputed_hash = compute_event_hash(ev)
    hash_ok = recomputed_hash == ev["event_hash"]

    result = {
        "event_id": event_id,
        "stored_hash": ev["event_hash"],
        "computed_hash": recomputed_hash,
        "hash_match": hash_ok,
        "batch_id": ev.get("batch_id"),
        "anchor_status": ev.get("anchor_status"),
    }

    if ev.get("batch_id") and ev.get("anchor_status") == "ANCHORED":
        batch_events = await get_batch_events(ev["batch_id"])
        all_hashes = [e["event_hash"] for e in batch_events]
        proof = compute_proof(all_hashes, ev["event_hash"])
        anchor = await get_anchor(ev["batch_id"])
        ledger_root = anchor["merkle_root"] if anchor else None
        proof_valid = verify_proof(ev["event_hash"], proof, ledger_root) if (proof and ledger_root) else False
        result.update({
            "merkle_proof": proof,
            "merkle_root_on_chain": ledger_root,
            "proof_valid": proof_valid,
        })
        result["verdict"] = "PASS" if (hash_ok and proof_valid) else "FAIL"
        result["reason"] = "Hash match + Merkle proof valid" if result["verdict"] == "PASS" \
            else "Hash or proof failed"
    else:
        result["verdict"] = "PASS" if hash_ok else "FAIL"
        result["reason"] = "Hash match (not yet anchored)" if hash_ok else "Hash mismatch - tampered"

    return result
