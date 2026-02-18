# API Specification

Base URL: `http://localhost:8080`  
Interactive docs (Swagger UI): `http://localhost:8080/docs`

## System

### GET /health

Returns gateway health status and operating mode.

```json
{
  "status": "ok",
  "stub_mode": true,
  "ts": "2024-11-15T10:00:00+00:00"
}
```

### GET /stats

Returns event counts grouped by type, severity, and zone.

## Events

### POST /events

Validate, hash, and submit a safety event to the immutable ledger.

Request body:

```json
{
  "event_type": "NEAR_MISS",
  "ts_event": "2024-11-15T09:17:45+00:00",
  "site_id": "site-torino-01",
  "zone_id": "Z04",
  "actor_id": "W001",
  "severity": "high",
  "source": "camera",
  "evidence_uri": "minio://audit-evidence/2024-11-15/near-miss-z04.mp4",
  "prev_event_hash": "",
  "payload_extra": {
    "clearance_m": 0.4,
    "equipment_id": "EQ-CRANE-01"
  }
}
```

Valid `event_type` values: `ZONE_ENTRY`, `ZONE_EXIT`, `PROXIMITY_ALERT`, `NEAR_MISS`, `PPE_VIOLATION`, `EQUIPMENT_FAULT`, `FALL_DETECTED`, `INTRUSION`, `GAS_ALERT`, `MANUAL_ALERT`

Valid `severity` values: `low`, `medium`, `high`, `critical`

Valid `source` values: `wearable`, `camera`, `gateway`, `simulator`, `manual`

Response `201`:

```json
{
  "event_id": "evt-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "tx_id": "abc123fabrictx",
  "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "ts_ingest": "2024-11-15T09:17:46+00:00",
  "status": "RECORDED"
}
```

### GET /events/{event_id}

Retrieve a single event record by ID.

### GET /events/{event_id}/history

Return the Fabric write history for an event key. Useful to confirm only one write occurred.

### GET /events

Query events with optional filters. Only one primary filter is applied per request.

| Parameter    | Description |
|-------------|-------------|
| `actor_id`  | Filter by worker or equipment ID |
| `zone_id`   | Filter by zone |
| `event_type`| Filter by event type |
| `severity`  | Filter by severity |
| `start_ts`  | Start of time range (ISO-8601, requires `end_ts`) |
| `end_ts`    | End of time range (ISO-8601, requires `start_ts`) |

Examples:

```bash
curl "http://localhost:8080/events?actor_id=W001"
curl "http://localhost:8080/events?zone_id=Z04"
curl "http://localhost:8080/events?severity=critical"
curl "http://localhost:8080/events?start_ts=2024-11-15T00:00:00Z&end_ts=2024-11-15T23:59:59Z"
```

## Integrity Verification

### POST /events/{event_id}/verify

Verify a payload against the hash stored on the ledger.

Request body:

```json
{
  "payload_json": "{\"actor_id\":\"W001\",\"event_type\":\"NEAR_MISS\",...}"
}
```

Response — match:

```json
{
  "event_id": "evt-abc...",
  "result": "PASS",
  "stored_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "computed_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "match": true
}
```

Response — mismatch (tamper detected):

```json
{
  "result": "FAIL: stored=e3b0c44298fc1c14 computed=ba7816bf8f01cfea",
  "match": false
}
```

## Audit

### GET /audit/report

Generate a JSON audit report. Accepts the same filter parameters as `GET /events`.

Response:

```json
{
  "generated_at": "2024-11-15T12:00:00+00:00",
  "filter_applied": {"zone_id": "Z04"},
  "event_count": 47,
  "events": [],
  "package_hash": "sha256-of-entire-bundle"
}
```

### GET /audit/package

Chaincode-level bundle generation. Returns events plus a package hash for chain-of-custody documentation.

Parameters:

- `filter_type`: `actor_id` | `zone_id` | `event_type` | `severity`
- `filter_value`: value to filter by

```bash
curl "http://localhost:8080/audit/package?filter_type=zone_id&filter_value=Z04"
```

## Error Responses

| Status | Meaning |
|--------|---------|
| 201 | Event recorded |
| 200 | Success |
| 404 | Event not found |
| 422 | Validation error — invalid schema |
| 502 | Fabric communication error |
