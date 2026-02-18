"""
ledger/besu.py - Hyperledger Besu adapter using web3.py.

Connects to the Besu node via JSON-RPC, loads the deployed AuditAnchor
contract, and calls storeBatchRoot(batchId, merkleRoot, metaHash).

Environment variables:
  BESU_RPC            - JSON-RPC endpoint (default: http://besu:8545)
  GATEWAY_PRIVATE_KEY - 32-byte hex private key of the authorised submitter
  CONTRACT_ADDRESS    - deployed AuditAnchor address (set by make deploy-contract)

The private key is never stored in the contract or on-chain. The address
derived from it is what's in authorisedSubmitters mapping.
"""
import json
import logging
import os
import asyncio
from pathlib import Path
from typing import Optional

log = logging.getLogger("audit.besu")

BESU_RPC    = os.getenv("BESU_RPC", "http://besu:8545")
PRIVATE_KEY = os.getenv("GATEWAY_PRIVATE_KEY",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
CONTRACT_ABI_PATH = Path("/app/contracts/deployed.json")

_w3 = None
_contract = None


def _load_web3():
    global _w3, _contract
    if _w3 is not None:
        return
    try:
        from web3 import Web3
        from web3.middleware import geth_poa_middleware

        _w3 = Web3(Web3.HTTPProvider(BESU_RPC))
        _w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        addr = CONTRACT_ADDRESS
        abi = None

        if CONTRACT_ABI_PATH.exists():
            deployed = json.loads(CONTRACT_ABI_PATH.read_text())
            abi = deployed.get("abi")
            if not addr:
                addr = deployed.get("address")

        if not addr or not abi:
            raise RuntimeError("CONTRACT_ADDRESS or ABI not configured")

        _contract = _w3.eth.contract(address=addr, abi=abi)
        log.info("Besu connected: %s  contract: %s", BESU_RPC, addr)
    except Exception as exc:
        log.error("Besu init failed: %s", exc)
        raise


def _bytes32(hex_str: str) -> bytes:
    """Convert a 64-char hex string to 32 bytes for Solidity bytes32."""
    return bytes.fromhex(hex_str.zfill(64))


async def anchor(batch_id: str, merkle_root: str, meta_hash: str):
    from . import adapter
    try:
        _load_web3()
        account = _w3.eth.account.from_key(PRIVATE_KEY)
        nonce = _w3.eth.get_transaction_count(account.address)

        tx = _contract.functions.storeBatchRoot(
            batch_id, _bytes32(merkle_root), _bytes32(meta_hash)
        ).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": 0,
        })
        signed = account.sign_transaction(tx)
        tx_hash = _w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        )
        block = _w3.eth.get_block(receipt.blockNumber)
        log.info("anchored batch_id=%s tx=%s block=%s",
                 batch_id, tx_hash.hex()[:16], receipt.blockNumber)
        return adapter.AnchorResult(tx_hash=tx_hash.hex(), block_ts=block.timestamp)
    except Exception as exc:
        log.error("Besu anchor failed: %s", exc)
        return adapter.AnchorResult(error=str(exc))


async def get_anchor(batch_id: str) -> Optional[dict]:
    try:
        _load_web3()
        root, meta, ts, submitter, exists = _contract.functions.getAnchor(batch_id).call()
        if not exists:
            return None
        return {
            "merkle_root": root.hex(),
            "meta_hash": meta.hex(),
            "block_ts": ts,
            "submitter": submitter,
        }
    except Exception as exc:
        log.error("Besu getAnchor failed: %s", exc)
        return None
