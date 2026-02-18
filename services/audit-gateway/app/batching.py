"""
batching.py - Periodic batch builder and anchor worker.

Runs as an asyncio background task. Every BATCH_WINDOW_SECONDS:
  1. Pull all PENDING events from PostgreSQL
  2. If none, skip
  3. Generate batch_id = "batch-<ts>-<uuid4[:8]>"
  4. Compute SHA-256 event_hash for each (if not already set)
  5. Build sorted Merkle tree over event_hashes → merkle_root
  6. Compute meta_hash = SHA256(canonical batch metadata)
  7. Write batch record to PostgreSQL
  8. Update events with batch_id, status=BATCHED
  9. Call ledger.anchor_batch(batch_id, merkle_root, meta_hash)
  10. On success: update batch status=ANCHORED, events status=ANCHORED
  11. On failure: reset events to PENDING for retry

This design answers the banca question "blockchain doesn't scale":
  - The ledger sees N batches per window, not N individual events
  - At 10 events/s and 5s window: 50 events per ledger write
  - At 100 events/s and 5s window: 500 events per ledger write
"""
import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from .db import (
    compute_meta_hash, get_pending_events, insert_batch,
    mark_events_anchored, mark_events_failed, mark_events_in_batch,
    update_batch_anchored, update_batch_failed, utc_now,
)
from .merkle import compute_root
from .ledger.adapter import anchor_batch

log = logging.getLogger("audit.batching")

BATCH_WINDOW_SECONDS = int(os.getenv("BATCH_WINDOW_SECONDS", "5"))
MIN_BATCH_SIZE = int(os.getenv("MIN_BATCH_SIZE", "1"))  # anchor even single events


async def batch_worker():
    """Main batch loop. Runs forever."""
    log.info("batch worker started: window=%ds min_size=%d", BATCH_WINDOW_SECONDS, MIN_BATCH_SIZE)
    while True:
        await asyncio.sleep(BATCH_WINDOW_SECONDS)
        try:
            await _close_batch()
        except Exception as exc:
            log.error("batch worker error: %s", exc)


async def _close_batch():
    window_end = utc_now()
    events = await get_pending_events(limit=1000)

    if len(events) < MIN_BATCH_SIZE:
        return

    window_start = min(e["ts_ingested"] for e in events)
    batch_id = f"batch-{window_end.replace(':', '-').replace('+', 'Z')}-{uuid.uuid4().hex[:8]}"
    site_ids = list({e["site_id"] for e in events})
    site_id = site_ids[0] if len(site_ids) == 1 else "multi"

    event_hashes = [e["event_hash"] for e in events]
    event_ids    = [e["event_id"]   for e in events]
    merkle_root  = compute_root(event_hashes)
    meta_hash    = compute_meta_hash(batch_id, window_start, window_end,
                                     len(events), site_id)

    log.info("closing batch %s: %d events  root=%s", batch_id, len(events), merkle_root[:16])

    batch = {
        "batch_id": batch_id,
        "window_start": window_start,
        "window_end": window_end,
        "event_count": len(events),
        "merkle_root": merkle_root,
        "meta_hash": meta_hash,
    }

    await insert_batch(batch)
    await mark_events_in_batch(event_ids, batch_id)

    result = await anchor_batch(batch_id, merkle_root, meta_hash)

    if result.success:
        await update_batch_anchored(batch_id, result.tx_hash, result.block_ts)
        await mark_events_anchored(batch_id)
        log.info("anchored batch %s  tx=%s", batch_id, result.tx_hash[:20] if result.tx_hash else "?")
    else:
        await update_batch_failed(batch_id)
        await mark_events_failed(batch_id)
        log.error("anchor failed for batch %s: %s", batch_id, result.error)
