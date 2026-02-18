"""
ledger/fabric.py - Hyperledger Fabric adapter (placeholder).

Swap in this adapter by setting LEDGER_BACKEND=fabric.
Implements the same interface as besu.py: anchor() and get_anchor().

Requires: Fabric Gateway SDK (pip install fabric-sdk-py or grpcio-based gateway)
"""
import logging
from typing import Optional

log = logging.getLogger("audit.fabric")


async def anchor(batch_id: str, merkle_root: str, meta_hash: str):
    from . import adapter
    # TODO: implement via Fabric chaincode RegisterBatch(batch_id, merkle_root, meta_hash)
    log.warning("Fabric adapter not yet implemented - using stub")
    return adapter.AnchorResult(error="Fabric adapter not implemented. Set LEDGER_BACKEND=besu or stub.")


async def get_anchor(batch_id: str) -> Optional[dict]:
    log.warning("Fabric adapter get_anchor not implemented")
    return None
