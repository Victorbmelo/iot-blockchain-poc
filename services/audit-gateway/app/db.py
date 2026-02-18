"""
db.py - PostgreSQL data access layer.

Tables:
  events  - individual safety events (operational store)
  batches - Merkle batch records
  anchors - on-chain anchor references (tx_hash, block_ts, status)

The Fabric/Besu ledger stores only batch_id + merkle_root + meta_hash.
Everything else lives here. The hash on the ledger is what makes this
an "immutable" audit layer - the ledger is the tamper-evident witness.
"""
import hashlib
import json
import logging
import os
import secrets
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg

log = logging.getLogger("audit.db")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://audit:audit@postgres:5432/auditdb",
)

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    return _pool


async def close_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


#  Schema 

CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    schema_version  TEXT    NOT NULL DEFAULT '1.0',
    event_type      TEXT    NOT NULL,
    ts              TEXT    NOT NULL,
    ts_ingested     TEXT    NOT NULL,
    site_id         TEXT    NOT NULL,
    zone_id         TEXT    NOT NULL,
    actor_id        TEXT    NOT NULL,
    severity        INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 5),
    source          TEXT    NOT NULL,
    payload         JSONB,
    event_hash      TEXT    NOT NULL,
    evidence_ref    TEXT,
    batch_id        TEXT,
    anchor_status   TEXT    NOT NULL DEFAULT 'PENDING'
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id        TEXT PRIMARY KEY,
    window_start    TEXT    NOT NULL,
    window_end      TEXT    NOT NULL,
    event_count     INTEGER NOT NULL,
    merkle_root     TEXT    NOT NULL,
    meta_hash       TEXT    NOT NULL,
    anchor_status   TEXT    NOT NULL DEFAULT 'PENDING',
    ledger_tx_hash  TEXT,
    ledger_block_ts BIGINT,
    created_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_actor    ON events (actor_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_zone     ON events (zone_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events (event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_batch    ON events (batch_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
"""


async def init_db():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(CREATE_SCHEMA)
    log.info("database schema initialised")


#  Hashing 

SCHEMA_VERSION = "1.0"

CANONICAL_FIELDS = [
    "schema_version", "event_type", "ts", "site_id",
    "zone_id", "actor_id", "severity", "source", "payload",
]


def _sort_keys(obj):
    if isinstance(obj, dict):
        return {k: _sort_keys(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_sort_keys(v) for v in obj]
    return obj


def compute_event_hash(event: dict) -> str:
    """SHA-256 of canonical JSON of the CANONICAL_FIELDS subset.

    Rules (answering the banca question 'what is in the hash'):
      - schema_version is always included (forward-compat marker)
      - payload is included (sensor readings - any change detected)
      - ts is included (timestamp forgery detected)
      - evidence_ref is excluded (set asynchronously)
      - nonce is excluded (used for idempotency ID generation only)

    Canonicalisation: keys sorted recursively, no whitespace, NFC unicode.
    """
    canonical = {k: event.get(k) for k in CANONICAL_FIELDS if event.get(k) is not None}
    canonical["schema_version"] = SCHEMA_VERSION
    raw = json.dumps(_sort_keys(canonical), separators=(",", ":"), ensure_ascii=False)
    raw = unicodedata.normalize("NFC", raw)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_event_id(event: dict) -> str:
    """Deterministic event_id from schema:actor:ts:type:zone:nonce.
    If nonce is absent, one is generated (non-idempotent retry).
    """
    nonce = event.get("nonce") or secrets.token_hex(8)
    parts = ":".join([
        SCHEMA_VERSION,
        event.get("actor_id", ""),
        event.get("ts", ""),
        event.get("event_type", ""),
        event.get("zone_id", ""),
        nonce,
    ])
    digest = hashlib.sha256(parts.encode()).hexdigest()[:32]
    return f"evt-{digest}"


def compute_meta_hash(batch_id: str, window_start: str, window_end: str,
                      event_count: int, site_id: str) -> str:
    """SHA-256 of canonical batch metadata. Stored on-chain alongside merkle_root."""
    meta = {
        "batch_id": batch_id,
        "window_start": window_start,
        "window_end": window_end,
        "event_count": event_count,
        "site_id": site_id,
    }
    raw = json.dumps(_sort_keys(meta), separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


#  Events 

async def insert_event(event: dict) -> dict:
    """Validate, hash, and insert a new event. Returns the stored record."""
    pool = await get_pool()
    event_id = generate_event_id(event)
    event_hash = compute_event_hash(event)
    ts_ingested = utc_now()

    async with pool.acquire() as conn:
        # Idempotency: return existing record if event_id already exists
        existing = await conn.fetchrow(
            "SELECT * FROM events WHERE event_id = $1", event_id
        )
        if existing:
            return dict(existing)

        await conn.execute("""
            INSERT INTO events
              (event_id, schema_version, event_type, ts, ts_ingested,
               site_id, zone_id, actor_id, severity, source,
               payload, event_hash, evidence_ref, anchor_status)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'PENDING')
        """,
            event_id, SCHEMA_VERSION,
            event["event_type"], event["ts"], ts_ingested,
            event["site_id"], event["zone_id"], event["actor_id"],
            event["severity"], event["source"],
            json.dumps(event.get("payload")) if event.get("payload") else None,
            event_hash, event.get("evidence_ref"),
        )

    return {
        "event_id": event_id, "schema_version": SCHEMA_VERSION,
        "event_type": event["event_type"], "ts": event["ts"],
        "ts_ingested": ts_ingested, "site_id": event["site_id"],
        "zone_id": event["zone_id"], "actor_id": event["actor_id"],
        "severity": event["severity"], "source": event["source"],
        "payload": event.get("payload"), "event_hash": event_hash,
        "evidence_ref": event.get("evidence_ref"),
        "batch_id": None, "anchor_status": "PENDING",
    }


async def get_event(event_id: str) -> Optional[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM events WHERE event_id=$1", event_id)
        if row:
            r = dict(row)
            if r.get("payload") and isinstance(r["payload"], str):
                r["payload"] = json.loads(r["payload"])
            return r
    return None


async def get_events(
    actor_id: str = None, zone_id: str = None, event_type: str = None,
    severity_min: int = 0, limit: int = 100, offset: int = 0
) -> list[dict]:
    pool = await get_pool()
    where, params, idx = [], [], 1
    if actor_id:
        where.append(f"actor_id = ${idx}"); params.append(actor_id); idx += 1
    if zone_id:
        where.append(f"zone_id = ${idx}"); params.append(zone_id); idx += 1
    if event_type:
        where.append(f"event_type = ${idx}"); params.append(event_type); idx += 1
    if severity_min > 0:
        where.append(f"severity >= ${idx}"); params.append(severity_min); idx += 1
    params += [limit, offset]
    sql = f"""SELECT * FROM events {"WHERE " + " AND ".join(where) if where else ""}
              ORDER BY ts DESC LIMIT ${idx} OFFSET ${idx+1}"""
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)
        result = []
        for r in rows:
            d = dict(r)
            if d.get("payload") and isinstance(d["payload"], str):
                d["payload"] = json.loads(d["payload"])
            result.append(d)
        return result


async def get_stats() -> dict:
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM events")
        by_type = dict(await conn.fetch(
            "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC"
        ))
        by_sev = dict(await conn.fetch(
            "SELECT severity::text, COUNT(*) AS n FROM events GROUP BY severity ORDER BY severity"
        ))
        by_zone = dict(await conn.fetch(
            "SELECT zone_id, COUNT(*) AS n FROM events GROUP BY zone_id ORDER BY n DESC LIMIT 10"
        ))
        pending = await conn.fetchval("SELECT COUNT(*) FROM events WHERE anchor_status='PENDING'")
        anchored = await conn.fetchval("SELECT COUNT(*) FROM events WHERE anchor_status='ANCHORED'")
    return {
        "total_events": total, "pending": pending, "anchored": anchored,
        "by_event_type": {r[0]: r[1] for r in (await _fetch_grouped(pool, "event_type"))},
        "by_severity":   {r[0]: r[1] for r in (await _fetch_grouped(pool, "severity"))},
        "by_zone":       {r[0]: r[1] for r in (await _fetch_grouped(pool, "zone_id", limit=10))},
    }


async def _fetch_grouped(pool, col, limit=50):
    async with pool.acquire() as conn:
        return await conn.fetch(
            f"SELECT {col}::text, COUNT(*) AS n FROM events GROUP BY {col} ORDER BY n DESC LIMIT {limit}"
        )


async def get_pending_events(limit=500) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM events WHERE anchor_status='PENDING' ORDER BY ts_ingested LIMIT $1",
            limit,
        )
        result = []
        for r in rows:
            d = dict(r)
            if d.get("payload") and isinstance(d["payload"], str):
                d["payload"] = json.loads(d["payload"])
            result.append(d)
        return result


async def mark_events_in_batch(event_ids: list[str], batch_id: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE events SET batch_id=$1, anchor_status='BATCHED' WHERE event_id=ANY($2::text[])",
            batch_id, event_ids,
        )


async def mark_events_anchored(batch_id: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE events SET anchor_status='ANCHORED' WHERE batch_id=$1", batch_id
        )


async def mark_events_failed(batch_id: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE events SET anchor_status='PENDING', batch_id=NULL WHERE batch_id=$1", batch_id
        )


#  Batches 

async def insert_batch(batch: dict) -> dict:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO batches
              (batch_id, window_start, window_end, event_count,
               merkle_root, meta_hash, anchor_status, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,'PENDING',$7)
            ON CONFLICT (batch_id) DO NOTHING
        """,
            batch["batch_id"], batch["window_start"], batch["window_end"],
            batch["event_count"], batch["merkle_root"], batch["meta_hash"], utc_now(),
        )
    return batch


async def update_batch_anchored(batch_id: str, tx_hash: str, block_ts: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE batches SET anchor_status='ANCHORED',
              ledger_tx_hash=$2, ledger_block_ts=$3
            WHERE batch_id=$1
        """, batch_id, tx_hash, block_ts)


async def update_batch_failed(batch_id: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE batches SET anchor_status='FAILED' WHERE batch_id=$1", batch_id
        )


async def get_batch(batch_id: str) -> Optional[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM batches WHERE batch_id=$1", batch_id)
        return dict(row) if row else None


async def get_batches(limit=50, offset=0) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM batches ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset
        )
        return [dict(r) for r in rows]


async def get_batch_events(batch_id: str) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM events WHERE batch_id=$1 ORDER BY ts", batch_id)
        result = []
        for r in rows:
            d = dict(r)
            if d.get("payload") and isinstance(d["payload"], str):
                d["payload"] = json.loads(d["payload"])
            result.append(d)
        return result
