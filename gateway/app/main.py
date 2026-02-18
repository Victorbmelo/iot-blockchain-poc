import json
import logging
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .schemas import (
    RegisterEventRequest, RegisterEventResponse,
    VerifyRequest, VerifyResponse, MetricsSummary, SCHEMA_VERSION,
)
from .hashing import (
    build_canonical_payload, compute_payload_hash,
    generate_event_id, generate_nonce, utc_now_iso,
)
from .signing import sign_payload_hash, signer_id, cert_fingerprint, verify_signature, public_key_pem
from .fabric_client import get_fabric_client, _stub_store
from .metrics import collector, EventMetric
from .roles import Role, ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, require_permission, get_role

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("audit_gateway")

_DEFAULT_FROM = "2000-01-01T00:00:00+00:00"
_DEFAULT_TO   = "2099-12-31T23:59:59+00:00"

app = FastAPI(
    title="Immutable Audit Gateway",
    description=(
        "REST API for submitting and querying IoT safety events on the "
        "Hyperledger Fabric audit ledger.\n\n"
        "**Role-based access**: pass `X-Role: contractor | safety_manager | inspector | insurer` "
        "header to simulate role-based permissions (Fabric mode uses MSP identity).\n\n"
        "Thesis: *Immutable Audit Layer for IoT Safety Data in Construction Sites* - "
        "Politecnico di Torino."
    ),
    version="1.0.0",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# System endpoints

@app.get("/health", tags=["system"])
def health():
    fc = get_fabric_client()
    return {
        "status": "ok",
        "stub_mode": fc._stub,
        "schema_version": SCHEMA_VERSION,
        "signer_id": signer_id(),
        "ts": utc_now_iso(),
    }


@app.get("/pubkey", tags=["system"],
         dependencies=[Depends(require_permission("read_pubkey"))])
def public_key():
    """Return the gateway ECDSA public key PEM.
    Verifiers use this to independently validate event signatures without
    contacting the gateway again.
    """
    return {
        "signer_id": signer_id(),
        "cert_fingerprint": cert_fingerprint(),
        "public_key_pem": public_key_pem(),
    }


@app.get("/roles", tags=["system"])
def list_roles():
    """Return the role definitions and permission matrix for this deployment."""
    return {
        "roles": {r.value: ROLE_DESCRIPTIONS[r] for r in Role},
        "permissions": {r.value: sorted(perms) for r, perms in ROLE_PERMISSIONS.items()},
        "note": (
            "In Fabric mode, role is determined by MSP identity attributes. "
            "In stub mode, pass X-Role header to simulate a role."
        ),
    }


@app.get("/stats", tags=["system"],
         dependencies=[Depends(require_permission("query_stats"))])
def stats():
    from collections import Counter
    events = list(_stub_store.values())
    return {
        "total_events": len(events),
        "by_event_type": dict(Counter(e.get("eventType") for e in events)),
        "by_severity":   dict(Counter(e.get("severity")  for e in events)),
        "by_zone":       dict(Counter(e.get("zoneId")    for e in events)),
    }


@app.get("/metrics", tags=["system"], response_model=MetricsSummary)
def metrics():
    """Runtime metrics: latency P50/P95/P99, throughput, error rate."""
    s = collector.summary()
    return MetricsSummary(
        run_id=s.run_id,
        started_at=s.started_at,
        total_submitted=s.total_submitted,
        total_success=s.total_success,
        total_failed=s.total_failed,
        avg_latency_ms=s.avg_latency_ms,
        p95_latency_ms=s.p95_latency_ms,
        p99_latency_ms=s.p99_latency_ms,
        throughput_tps=s.throughput_tps,
    )


@app.post("/metrics/export", tags=["system"])
def export_metrics():
    """Write events.csv + metrics.csv to results/ directory."""
    path = collector.export()
    return {"exported_to": path, "run_id": collector.run_id}



# Event write endpoint - contractor role only


@app.post("/events", response_model=RegisterEventResponse, tags=["events"], status_code=201)
def register_event(
    body: RegisterEventRequest,
    role: Role = Depends(require_permission("submit_event")),
):
    """Validate, hash, sign, and submit a safety event to the immutable ledger.

    **Access**: contractor only.

    Processing steps:
    1. Validate schema against SafetyEvent v1.0 contract
    2. Compute deterministic eventId (idempotent across retries with same nonce)
    3. Build canonical payload and compute SHA-256 hash
    4. Sign payloadHash with gateway ECDSA-P256 key
    5. Submit to Fabric chaincode (or in-memory stub)
    6. Record latency metric
    """
    nonce = body.nonce or generate_nonce()
    event_id = generate_event_id(
        SCHEMA_VERSION, body.actor_id, body.ts, body.event_type, body.zone_id, nonce
    )

    canonical = build_canonical_payload({"schema_version": SCHEMA_VERSION, **body.model_dump()})
    payload_hash = compute_payload_hash(canonical)
    signature = sign_payload_hash(payload_hash)

    t0 = time.monotonic()
    success = False
    tx_id = ""
    error_msg = None

    try:
        tx_id = get_fabric_client().register_event(
            event_id=event_id,
            event_type=body.event_type,
            actor_id=body.actor_id,
            site_id=body.site_id,
            zone_id=body.zone_id,
            ts=body.ts,
            severity=body.severity,
            source=body.source,
            payload_hash=payload_hash,
            evidence_ref=body.evidence_ref or "",
            prev_event_hash=body.prev_event_hash or "",
            signature=signature,
            signer_id=signer_id(),
            signer_cert_fingerprint=cert_fingerprint(),
        )
        success = True
    except Exception as exc:
        error_msg = str(exc)
        log.error("fabric submit failed: %s", exc)
    finally:
        latency_ms = (time.monotonic() - t0) * 1000
        collector.record(EventMetric(
            ts=utc_now_iso(),
            event_id=event_id,
            event_type=body.event_type,
            severity=body.severity,
            zone_id=body.zone_id,
            actor_id=body.actor_id,
            latency_ms=round(latency_ms, 2),
            success=success,
            error=error_msg,
        ))

    if not success:
        raise HTTPException(status_code=502, detail=error_msg)

    log.info("registered event_id=%s tx_id=%s latency_ms=%.1f role=%s",
             event_id, tx_id, latency_ms, role)

    return RegisterEventResponse(
        event_id=event_id,
        tx_id=tx_id,
        payload_hash=payload_hash,
        signature=signature,
        signer_id=signer_id(),
        signer_cert_fingerprint=cert_fingerprint(),
        ts_ledger=utc_now_iso(),
    )



# Event read endpoints


@app.get("/events/{event_id}", tags=["events"],
         dependencies=[Depends(require_permission("read_events"))])
def get_event(event_id: str):
    """Retrieve a single event by ID. Access: safety_manager, inspector, insurer."""
    try:
        return get_fabric_client().query_event(event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/events/{event_id}/history", tags=["events"],
         dependencies=[Depends(require_permission("read_history"))])
def get_event_history(event_id: str):
    """Return Fabric write history for an event.
    A legitimate record has exactly one write entry.
    Two or more entries indicate a modification attempt.
    Access: inspector only.
    """
    try:
        return get_fabric_client().get_history(event_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/events/{event_id}/chain", tags=["events"],
         dependencies=[Depends(require_permission("trace_chain"))])
def trace_chain(event_id: str):
    """Follow the prevEventHash chain from this event backward.
    A broken link (missing event or hash mismatch) indicates selective deletion.
    Access: inspector only.
    """
    try:
        return get_fabric_client().trace_chain(event_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/events", tags=["events"],
         dependencies=[Depends(require_permission("read_events"))])
def list_events(
    event_type: Optional[str] = Query(None),
    from_ts: str = Query(default=_DEFAULT_FROM),
    to_ts:   str = Query(default=_DEFAULT_TO),
    page_size: int = Query(default=50, ge=1, le=500),
    bookmark:  str = Query(default=""),
):
    """List events with optional event_type filter. Access: safety_manager, inspector, insurer."""
    try:
        if event_type:
            return get_fabric_client().get_events_by_type(event_type, from_ts, to_ts, page_size, bookmark)
        fc = get_fabric_client()
        if fc._stub:
            all_events = fc.query_all()
            return {"records": all_events, "fetchedCount": len(all_events), "bookmark": ""}
        return get_fabric_client().get_events_by_type("", from_ts, to_ts, page_size, bookmark)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/actors/{actor_id}/events", tags=["events"],
         dependencies=[Depends(require_permission("read_events"))])
def get_actor_events(
    actor_id:  str,
    from_ts:   str = Query(default=_DEFAULT_FROM),
    to_ts:     str = Query(default=_DEFAULT_TO),
    page_size: int = Query(default=50, ge=1, le=500),
    bookmark:  str = Query(default=""),
):
    """Paginated event history for a specific actor. Access: safety_manager, inspector, insurer."""
    try:
        return get_fabric_client().get_events_by_actor(actor_id, from_ts, to_ts, page_size, bookmark)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/zones/{zone_id}/events", tags=["events"],
         dependencies=[Depends(require_permission("read_events"))])
def get_zone_events(
    zone_id:   str,
    from_ts:   str = Query(default=_DEFAULT_FROM),
    to_ts:     str = Query(default=_DEFAULT_TO),
    page_size: int = Query(default=50, ge=1, le=500),
    bookmark:  str = Query(default=""),
):
    """Paginated event history for a specific zone. Access: safety_manager, inspector, insurer."""
    try:
        return get_fabric_client().get_events_by_zone(zone_id, from_ts, to_ts, page_size, bookmark)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/near-misses", tags=["events"],
         dependencies=[Depends(require_permission("read_near_misses"))])
def get_near_misses(
    from_ts:   str = Query(default=_DEFAULT_FROM),
    to_ts:     str = Query(default=_DEFAULT_TO),
    page_size: int = Query(default=50, ge=1, le=500),
    bookmark:  str = Query(default=""),
):
    """All NEAR_MISS events (paginated). Access: safety_manager, inspector."""
    try:
        return get_fabric_client().get_near_misses(from_ts, to_ts, page_size, bookmark)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))



# Integrity verification - inspector and insurer


@app.post("/verify", tags=["integrity"])
def verify_event(
    event_id: str = Query(...),
    body: VerifyRequest = ...,
    role: Role = Depends(require_permission("verify_event")),
):
    """Verify a payload hash against the stored on-chain hash, and validate the gateway signature.

    The caller provides the SHA-256 hash of their local copy of the payload.
    The endpoint returns:
    - PASS if it matches the on-chain hash
    - FAIL with stored/submitted hashes if it does not match
    - signature_valid: whether the ECDSA signature is authentic

    Access: inspector, insurer.
    """
    try:
        stored = get_fabric_client().query_event(event_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"event {event_id} not found")

    stored_hash = stored.get("payloadHash", "")
    match = body.payload_hash == stored_hash
    result_str = "PASS" if match else f"FAIL: stored={stored_hash[:16]}... submitted={body.payload_hash[:16]}..."

    sig_valid = None
    if stored.get("signature"):
        sig_valid = verify_signature(stored_hash, stored["signature"])

    log.info("verify event_id=%s result=%s sig_valid=%s role=%s",
             event_id, result_str, sig_valid, role)

    return VerifyResponse(
        event_id=event_id,
        result=result_str,
        stored_hash=stored_hash,
        submitted_hash=body.payload_hash,
        signature_valid=sig_valid,
        match=match,
    )



# Audit export - inspector only


@app.get("/audit/report", tags=["audit"],
         dependencies=[Depends(require_permission("export_audit_report"))])
def export_audit_report(
    filter_type:  str = Query(..., description="actor_id | zone_id | event_type"),
    filter_value: str = Query(...),
    from_ts: str = Query(default=_DEFAULT_FROM),
    to_ts:   str = Query(default=_DEFAULT_TO),
):
    """Generate a tamper-evident audit package for a specific actor, zone, or event type.
    Includes a packageHash covering all returned events.
    Access: inspector only.
    """
    try:
        return get_fabric_client().get_audit_package(filter_type, filter_value, from_ts, to_ts)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
