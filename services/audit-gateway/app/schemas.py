"""
schemas.py - Event and batch data contracts.

These are the formal definitions referenced in docs/audit-event-contract.md.
Any change to EventIn must be reflected in:
  - The list of CANONICAL_FIELDS (determines what the hash covers)
  - Chapter 4 data model table
"""
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator
import re

SCHEMA_VERSION = "1.0"

# Fields included in the canonical hash (order irrelevant - keys are sorted).
# Fields NOT in this list (nonce, evidence_ref, prev_event_hash) are excluded
# because they may not be known at submission time or are metadata-only.
CANONICAL_FIELDS = [
    "schema_version", "event_type", "ts", "site_id",
    "zone_id", "actor_id", "severity", "source", "payload",
]


class EventType(str, Enum):
    ZONE_ENTRY       = "ZONE_ENTRY"
    ZONE_EXIT        = "ZONE_EXIT"
    HAZARD_ENTRY     = "HAZARD_ENTRY"
    PROXIMITY_ALERT  = "PROXIMITY_ALERT"
    NEAR_MISS        = "NEAR_MISS"
    PPE_VIOLATION    = "PPE_VIOLATION"
    EQUIPMENT_FAULT  = "EQUIPMENT_FAULT"
    FALL_DETECTED    = "FALL_DETECTED"
    GAS_ALERT        = "GAS_ALERT"
    INTRUSION        = "INTRUSION"
    MANUAL_ALERT     = "MANUAL_ALERT"


class Source(str, Enum):
    WEARABLE     = "wearable"
    CAMERA       = "camera"
    PROXIMITY    = "proximity_tag"
    GATEWAY      = "gateway"
    SIMULATOR    = "simulator"
    MANUAL       = "manual"


class EventIn(BaseModel):
    """Input schema for POST /events. Validated at gateway ingress."""

    # Identity
    event_type: EventType
    ts:         str   = Field(..., description="ISO-8601 UTC timestamp at event source")
    site_id:    str   = Field(..., max_length=64)
    zone_id:    str   = Field(..., max_length=16)
    actor_id:   str   = Field(..., max_length=32,
                              description="Pseudonymised worker or equipment ID. No PII.")
    severity:   int   = Field(..., ge=0, le=5)
    source:     Source

    # Payload (optional - small sensor reading or minimal metadata)
    payload:    Optional[dict[str, Any]] = Field(
        default=None,
        description="Small sensor payload (<4KB). Included in canonical hash."
    )

    # Metadata (excluded from hash - set after submission or asynchronously)
    nonce:          Optional[str] = Field(default=None, max_length=64,
                                          description="Caller nonce for idempotency")
    evidence_ref:   Optional[str] = Field(default=None, max_length=512,
                                          description="URI of large evidence file in MinIO/IPFS")

    @field_validator("ts")
    @classmethod
    def validate_ts(cls, v: str) -> str:
        # Accept ISO-8601 with Z or +00:00
        if not re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", v):
            raise ValueError("ts must be ISO-8601 UTC (e.g. 2024-11-15T09:00:00Z)")
        return v


class EventOut(BaseModel):
    """Stored event record (from PostgreSQL, returned by GET /events)."""
    event_id:       str
    schema_version: str
    event_type:     str
    ts:             str
    ts_ingested:    str
    site_id:        str
    zone_id:        str
    actor_id:       str
    severity:       int
    source:         str
    payload:        Optional[dict] = None
    event_hash:     str   = Field(..., description="SHA-256 of canonical payload")
    evidence_ref:   Optional[str] = None
    batch_id:       Optional[str] = None
    anchor_status:  str   = "PENDING"


class BatchOut(BaseModel):
    """Batch anchor record."""
    batch_id:       str
    window_start:   str
    window_end:     str
    event_count:    int
    merkle_root:    str
    meta_hash:      str
    anchor_status:  str    # PENDING | ANCHORED | FAILED
    ledger_tx_hash: Optional[str] = None
    ledger_block_ts: Optional[int] = None


class VerifyResult(BaseModel):
    """Result of a batch or event integrity verification."""
    verdict:        str   # PASS | FAIL
    reason:         str
    batch_id:       Optional[str] = None
    event_count:    int   = 0
    events_ok:      int   = 0
    events_tampered: int  = 0
    events_missing: int   = 0
    merkle_root_computed:  Optional[str] = None
    merkle_root_on_chain:  Optional[str] = None
    roots_match:    Optional[bool] = None
