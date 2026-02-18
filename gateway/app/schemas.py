from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


SCHEMA_VERSION = "1.0"


class EventType(str, Enum):
    ZONE_ENTRY = "ZONE_ENTRY"
    ZONE_EXIT = "ZONE_EXIT"
    PROXIMITY_ALERT = "PROXIMITY_ALERT"
    NEAR_MISS = "NEAR_MISS"
    PPE_VIOLATION = "PPE_VIOLATION"
    EQUIPMENT_FAULT = "EQUIPMENT_FAULT"
    FALL_DETECTED = "FALL_DETECTED"
    INTRUSION = "INTRUSION"
    GAS_ALERT = "GAS_ALERT"
    MANUAL_ALERT = "MANUAL_ALERT"
    HAZARD_ENTRY = "HAZARD_ENTRY"


class Source(str, Enum):
    WEARABLE = "wearable"
    CAMERA = "camera"
    PROXIMITY_TAG = "proximity_tag"
    GATEWAY = "gateway"
    SIMULATOR = "simulator"
    MANUAL = "manual"


class RegisterEventRequest(BaseModel):
    """Inbound event from the IoT platform or simulator.

    actorId is treated as a pseudonym — no PII should be stored here.
    Sensitive context goes in payload_extra, which is hashed and stored off-chain.
    """
    event_type: EventType
    ts: str = Field(..., description="ISO-8601 UTC timestamp of the event at the source")
    site_id: str = Field(..., min_length=1, max_length=64)
    zone_id: str = Field(..., min_length=1, max_length=64)
    actor_id: str = Field(..., min_length=1, max_length=64,
                          description="Pseudonymised worker or equipment identifier")
    severity: int = Field(..., ge=0, le=5, description="Severity scale 0 (informational) to 5 (critical)")
    source: Source
    evidence_ref: Optional[str] = Field(default="", description="URI of off-chain evidence (MinIO, IPFS)")
    prev_event_hash: Optional[str] = Field(default="",
                                           description="payloadHash of previous event in the actor chain")
    nonce: Optional[str] = Field(default="", description="Random value to ensure eventId uniqueness on retry")
    payload_extra: Optional[dict] = Field(default=None,
                                          description="Additional sensor data — stored off-chain and hashed")

    @field_validator("ts")
    @classmethod
    def validate_iso8601(cls, value: str) -> str:
        import datetime
        try:
            datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"ts must be ISO-8601, got: {value}")
        return value


class RegisterEventResponse(BaseModel):
    event_id: str
    tx_id: str
    payload_hash: str
    signature: str
    signer_id: str
    signer_cert_fingerprint: str
    ts_ledger: str
    schema_version: str = SCHEMA_VERSION
    status: str = "RECORDED"


class VerifyRequest(BaseModel):
    payload_hash: str = Field(..., description="SHA-256 hex digest of the canonical payload to verify")


class VerifyResponse(BaseModel):
    event_id: str
    result: str
    stored_hash: str
    submitted_hash: str
    signature_valid: Optional[bool] = None
    match: bool


class MetricsSummary(BaseModel):
    run_id: str
    started_at: str
    total_submitted: int
    total_success: int
    total_failed: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_tps: float
