"""
Database models for the Audit Gateway.

Three tables:
  events  - individual safety events (operational store)
  batches - groups of events committed per time window
  anchors - ledger anchor records (tx_id, block number, status)

The ledger stores only the Merkle root; Postgres stores the events.
Verification works by recomputing the root from events and comparing
it to what is on-chain.
"""
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Column, DateTime,
    ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class AnchorStatus(str, PyEnum):
    PENDING  = "PENDING"
    ANCHORED = "ANCHORED"
    FAILED   = "FAILED"


class Event(Base):
    """A single safety event from the construction site.

    event_hash = SHA256(canonical_json({event_id, ts, actor_id, site_id, zone_id,
                                        event_type, severity, source, payload_hash}))
    This hash is a leaf in the batch Merkle tree.
    """
    __tablename__ = "events"

    id            = Column(Integer, primary_key=True, autoincrement=True)

    # Identity
    event_id      = Column(String(64), nullable=False, unique=True, index=True)

    # Timestamps
    ts            = Column(DateTime(timezone=True), nullable=False, index=True)
    received_at   = Column(DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    # Location
    actor_id      = Column(String(64), nullable=False, index=True)
    site_id       = Column(String(64), nullable=False)
    zone_id       = Column(String(64), nullable=False, index=True)

    # Classification
    event_type    = Column(String(32), nullable=False, index=True)
    severity      = Column(Integer, nullable=False)
    source        = Column(String(32), nullable=False)

    # Payload
    payload       = Column(JSONB, nullable=True)   # full sensor payload (off-chain equivalent)
    payload_hash  = Column(String(64), nullable=False)  # SHA256(canonical(payload))

    # Integrity
    event_hash    = Column(String(64), nullable=False, unique=True)  # leaf in Merkle tree
    prev_event_hash = Column(String(64), nullable=True)  # actor-level chain

    # Batch linkage
    batch_id      = Column(String(64), ForeignKey("batches.batch_id"), nullable=True, index=True)

    # Relations
    batch         = relationship("Batch", back_populates="events")

    __table_args__ = (
        CheckConstraint("severity BETWEEN 0 AND 5", name="ck_events_severity"),
        CheckConstraint("length(event_hash) = 64",  name="ck_events_hash_len"),
    )

    def __repr__(self) -> str:
        return f"<Event id={self.event_id[:12]} type={self.event_type} actor={self.actor_id}>"


class Batch(Base):
    """A closed time-window batch of events ready for anchoring.

    The batch's Merkle root is computed from all event_hash values in the window
    and anchored on-chain. This separates write throughput (Postgres) from
    blockchain commit latency.
    """
    __tablename__ = "batches"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    batch_id      = Column(String(64), nullable=False, unique=True, index=True)

    # Time window
    window_start  = Column(DateTime(timezone=True), nullable=False)
    window_end    = Column(DateTime(timezone=True), nullable=False)

    # Content
    event_count   = Column(Integer, nullable=False)
    site_id       = Column(String(64), nullable=False)

    # Integrity
    merkle_root   = Column(String(64), nullable=False)   # Merkle root of event hashes
    meta_hash     = Column(String(64), nullable=False)   # SHA256(batch metadata)

    # Anchor status
    anchor_status = Column(String(16), nullable=False, default=AnchorStatus.PENDING.value)
    ledger_tx_id  = Column(String(128), nullable=True)
    ledger_block  = Column(BigInteger, nullable=True)
    anchor_latency_ms = Column(Integer, nullable=True)  # wall-clock anchor time

    # Timestamps
    created_at    = Column(DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    anchored_at   = Column(DateTime(timezone=True), nullable=True)

    # Relations
    events        = relationship("Event", back_populates="batch")

    def __repr__(self) -> str:
        return (f"<Batch {self.batch_id[:12]} events={self.event_count} "
                f"status={self.anchor_status}>")
