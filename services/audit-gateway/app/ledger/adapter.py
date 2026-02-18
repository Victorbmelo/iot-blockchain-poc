"""
ledger/adapter.py - Abstract ledger interface.

The gateway calls anchor_batch() without knowing whether the backend is
Besu, Fabric, or a test stub. Swapping backends requires only changing
LEDGER_BACKEND env var, not the gateway logic.

This is the "adapter" pattern described in the architecture doc.
"""
import logging
import os
from typing import Optional

log = logging.getLogger("audit.ledger")

BACKEND = os.getenv("LEDGER_BACKEND", "stub")  # stub | besu | fabric


class AnchorResult:
    __slots__ = ("tx_hash", "block_ts", "error")
    def __init__(self, tx_hash: Optional[str] = None,
                 block_ts: Optional[int] = None,
                 error: Optional[str] = None):
        self.tx_hash = tx_hash
        self.block_ts = block_ts
        self.error = error

    @property
    def success(self) -> bool:
        return self.error is None and self.tx_hash is not None


async def anchor_batch(batch_id: str, merkle_root: str, meta_hash: str) -> AnchorResult:
    """Anchor a batch root to the ledger. Returns AnchorResult."""
    if BACKEND == "besu":
        from .besu import anchor as besu_anchor
        return await besu_anchor(batch_id, merkle_root, meta_hash)
    elif BACKEND == "fabric":
        from .fabric import anchor as fabric_anchor
        return await fabric_anchor(batch_id, merkle_root, meta_hash)
    else:
        return await _stub_anchor(batch_id, merkle_root, meta_hash)


#  Stub backend 

_stub_store: dict[str, dict] = {}
_stub_counter = 0


async def _stub_anchor(batch_id: str, merkle_root: str, meta_hash: str) -> AnchorResult:
    global _stub_counter
    import time
    _stub_counter += 1
    tx_hash = f"0xstub{_stub_counter:08x}{'a' * 56}"
    block_ts = int(time.time())
    _stub_store[batch_id] = {
        "merkle_root": merkle_root, "meta_hash": meta_hash,
        "tx_hash": tx_hash, "block_ts": block_ts,
    }
    log.info("stub anchor batch_id=%s root=%s tx=%s", batch_id, merkle_root[:16], tx_hash[:16])
    return AnchorResult(tx_hash=tx_hash, block_ts=block_ts)


async def get_anchor(batch_id: str) -> Optional[dict]:
    """Read an anchor from the ledger. Used by the verifier."""
    if BACKEND == "besu":
        from .besu import get_anchor as besu_get
        return await besu_get(batch_id)
    elif BACKEND == "fabric":
        from .fabric import get_anchor as fabric_get
        return await fabric_get(batch_id)
    else:
        return _stub_store.get(batch_id)
