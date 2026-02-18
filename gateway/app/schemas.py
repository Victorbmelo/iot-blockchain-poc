from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


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


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Source(str, Enum):
    WEARABLE = "wearable"
    CAMERA = "camera"
    GATEWAY = "gateway"
    SIMULATOR = "simulator"
    MANUAL = "manual"


class RegisterEventRequest(BaseModel):
    event_type: EventType
    ts_event: str = Field(..., description="ISO-8601 UTC timestamp of the event occurrence")
    site_id: str = Field(..., min_length=1, max_length=64)
    zone_id: str = Field(..., min_length=1, max_length=64)
    actor_id: str = Field(..., min_length=1, max_length=64)
    severity: Severity
    source: Source
    evidence_uri: Optional[str] = Field(default="")
    prev_event_hash: Optional[str] = Field(default="")
    payload_extra: Optional[dict] = Field(default=None, description="Additional sensor data stored off-chain")

    @field_validator("ts_event")
    @classmethod
    def validate_iso8601(cls, value: str) -> str:
        import datetime
        try:
            datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"ts_event must be ISO-8601, got: {value}")
        return value


class RegisterEventResponse(BaseModel):
    event_id: str
    tx_id: str
    payload_hash: str
    ts_ingest: str
    status: str = "RECORDED"


class VerifyRequest(BaseModel):
    payload_json: str = Field(..., description="Raw JSON string of the original payload to verify")


class VerifyResponse(BaseModel):
    event_id: str
    result: str
    stored_hash: str
    computed_hash: str
    match: bool
