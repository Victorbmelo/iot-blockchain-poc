import json
import logging
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .schemas import RegisterEventRequest, RegisterEventResponse, VerifyRequest, VerifyResponse
from .hashing import build_canonical_payload, compute_payload_hash, compute_string_hash, generate_event_id, utc_now_iso
from .fabric_client import get_fabric_client, _stub_store

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("audit_gateway")

app = FastAPI(
    title="Immutable Audit Gateway",
    description=(
        "REST API for submitting and querying IoT safety events "
        "on the Hyperledger Fabric audit ledger. "
        "Thesis: Immutable Audit Layer for IoT Safety Data in Construction Sites — "
        "Politecnico di Torino."
    ),
    version="1.0.0",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health", tags=["system"])
def health():
    fc = get_fabric_client()
    return {"status": "ok", "stub_mode": fc._stub, "ts": utc_now_iso()}


@app.get("/stats", tags=["system"])
def stats():
    from collections import Counter
    events = list(_stub_store.values())
    return {
        "total_events": len(events),
        "by_event_type": dict(Counter(e.get("event_type") for e in events)),
        "by_severity": dict(Counter(e.get("severity") for e in events)),
        "by_zone": dict(Counter(e.get("zone_id") for e in events)),
    }


@app.post("/events", response_model=RegisterEventResponse, tags=["events"], status_code=201)
def register_event(body: RegisterEventRequest):
    """Validate, hash, and submit a safety event to the immutable ledger."""
    event_id = generate_event_id(body.site_id, body.actor_id, body.ts_event, body.event_type)
    payload_hash = compute_payload_hash(build_canonical_payload(body.model_dump()))

    try:
        tx_id = get_fabric_client().register_event(
            event_id=event_id,
            event_type=body.event_type,
            ts_event=body.ts_event,
            site_id=body.site_id,
            zone_id=body.zone_id,
            actor_id=body.actor_id,
            severity=body.severity,
            source=body.source,
            payload_hash=payload_hash,
            evidence_uri=body.evidence_uri or "",
            prev_event_hash=body.prev_event_hash or "",
        )
    except Exception as exc:
        log.error("fabric submit failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))

    log.info("registered event_id=%s tx_id=%s", event_id, tx_id)
    return RegisterEventResponse(
        event_id=event_id,
        tx_id=tx_id,
        payload_hash=payload_hash,
        ts_ingest=utc_now_iso(),
    )


@app.get("/events/{event_id}", tags=["events"])
def get_event(event_id: str):
    try:
        return get_fabric_client().query_event(event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/events/{event_id}/history", tags=["events"])
def get_event_history(event_id: str):
    """Return the Fabric write history for an event (tamper evidence)."""
    try:
        return get_fabric_client().get_history(event_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/events", tags=["events"])
def list_events(
    actor_id: Optional[str] = Query(None),
    zone_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    start_ts: Optional[str] = Query(None),
    end_ts: Optional[str] = Query(None),
):
    """Query events by a single filter. For audit bundles use /audit/report."""
    fc = get_fabric_client()
    try:
        if actor_id:
            return fc.query_by_worker(actor_id)
        if zone_id:
            return fc.query_by_zone(zone_id)
        if event_type:
            return fc.query_by_event_type(event_type)
        if severity:
            return fc.query_by_severity(severity)
        if start_ts and end_ts:
            return fc.query_by_time_range(start_ts, end_ts)
        return fc.query_by_time_range("2000-01-01T00:00:00Z", "2099-12-31T23:59:59Z")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/events/{event_id}/verify", response_model=VerifyResponse, tags=["integrity"])
def verify_integrity(event_id: str, body: VerifyRequest):
    """Verify a payload against the hash stored on the ledger. Returns PASS or FAIL."""
    try:
        stored_event = get_fabric_client().query_event(event_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"event {event_id} not found")

    stored_hash = stored_event.get("payload_hash", "")
    computed_hash = compute_string_hash(body.payload_json)
    match = computed_hash == stored_hash
    result = "PASS" if match else f"FAIL: stored={stored_hash[:16]} computed={computed_hash[:16]}"

    log.info("integrity check event_id=%s result=%s", event_id, result)
    return VerifyResponse(
        event_id=event_id,
        result=result,
        stored_hash=stored_hash,
        computed_hash=computed_hash,
        match=match,
    )


@app.get("/audit/report", tags=["audit"])
def export_audit_report(
    actor_id: Optional[str] = Query(None),
    zone_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    start_ts: Optional[str] = Query(None),
    end_ts: Optional[str] = Query(None),
):
    """Generate a JSON audit report suitable for forensic investigation."""
    fc = get_fabric_client()
    try:
        if actor_id:
            events, filter_desc = fc.query_by_worker(actor_id), {"actor_id": actor_id}
        elif zone_id:
            events, filter_desc = fc.query_by_zone(zone_id), {"zone_id": zone_id}
        elif event_type:
            events, filter_desc = fc.query_by_event_type(event_type), {"event_type": event_type}
        elif severity:
            events, filter_desc = fc.query_by_severity(severity), {"severity": severity}
        elif start_ts and end_ts:
            events, filter_desc = fc.query_by_time_range(start_ts, end_ts), {"start_ts": start_ts, "end_ts": end_ts}
        else:
            events, filter_desc = fc.query_by_time_range("2000-01-01T00:00:00Z", "2099-12-31T23:59:59Z"), {"filter": "ALL"}

        normalised = [e["record"] if isinstance(e, dict) and "record" in e else e for e in events]

        import hashlib
        pkg_hash = hashlib.sha256(json.dumps(normalised, sort_keys=True).encode()).hexdigest()

        return {
            "generated_at": utc_now_iso(),
            "filter_applied": filter_desc,
            "event_count": len(normalised),
            "events": normalised,
            "package_hash": pkg_hash,
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/audit/package", tags=["audit"])
def get_audit_package(
    filter_type: str = Query(..., description="One of: actor_id, zone_id, event_type, severity"),
    filter_value: str = Query(...),
):
    """Return a chaincode-level audit bundle with package hash for chain-of-custody."""
    try:
        return get_fabric_client().get_audit_package(filter_type, filter_value)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
