"""
ledger/besu.py - Hyperledger Besu adapter using web3.py.

Connects to the Besu node via JSON-RPC, loads the deployed AuditAnchor
contract, and calls storeBatchRoot(batchId, merkleRoot, metaHash).

Environment variables:
  BESU_RPC            - JSON-RPC endpoint (default: http://besu:8545)
  GATEWAY_PRIVATE_KEY - 32-byte hex private key of the authorised submitter
  CONTRACT_ADDRESS    - deployed AuditAnchor address (optional if deployed.json exists)

The private key is never stored in the contract or on-chain. The address
derived from it is what's in authorisedSubmitters mapping.
"""
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger("audit.besu")

BESU_RPC = os.getenv("BESU_RPC", "http://besu:8545")
PRIVATE_KEY = os.getenv(
    "GATEWAY_PRIVATE_KEY",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
)
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
CONTRACT_ABI_PATH = Path("/app/contracts/deployed.json")

_w3 = None
_contract = None


def _load_web3():
    global _w3, _contract
    if _w3 is not None:
        return

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
        raise RuntimeError("CONTRACT_ADDRESS or ABI not configured (missing deployed.json?)")

    _contract = _w3.eth.contract(address=addr, abi=abi)
    log.info("Besu connected: rpc=%s contract=%s", BESU_RPC, addr)


def _bytes32(hex_str: str) -> bytes:
    """
    Convert hex string to 32 bytes for Solidity bytes32.

    Accepts with/without 0x prefix. Left-pads with zeros to 32 bytes.
    """
    s = (hex_str or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) > 64:
        raise ValueError(f"hex too long for bytes32: {len(s)} chars")
    return bytes.fromhex(s.zfill(64))


def _get_raw_tx(signed) -> bytes:
    # web3.py differs across versions: rawTransaction vs raw_transaction
    raw = getattr(signed, "rawTransaction", None)
    if raw is None:
        raw = getattr(signed, "raw_transaction", None)
    if raw is None:
        raise RuntimeError("SignedTransaction missing raw tx bytes (rawTransaction/raw_transaction)")
    return raw


async def anchor(batch_id: str, merkle_root: str, meta_hash: str):
    from . import adapter

    try:
        _load_web3()

        account = _w3.eth.account.from_key(PRIVATE_KEY)
        mr = _bytes32(merkle_root)
        mh = _bytes32(meta_hash)

        # ---- preflight: simulate call to catch revert reasons (auth / duplicate / zero root)
        try:
            _contract.functions.storeBatchRoot(batch_id, mr, mh).call({"from": account.address})
        except Exception as exc:
            return adapter.AnchorResult(error=f"preflight revert: {exc}")

        nonce = _w3.eth.get_transaction_count(account.address)

        base_tx = {
            "from": account.address,
            "nonce": nonce,
            "gasPrice": 0,
        }

        fn = _contract.functions.storeBatchRoot(batch_id, mr, mh)

        # ---- critical fix: estimate gas (strings are expensive; 200k often OOG)
        try:
            est = fn.estimate_gas(base_tx)
            gas_limit = int(est * 1.30) + 50_000  # margin
        except Exception:
            gas_limit = 500_000  # safe fallback

        tx = fn.build_transaction({**base_tx, "gas": gas_limit})

        signed = account.sign_transaction(tx)
        raw = _get_raw_tx(signed)

        tx_hash = _w3.eth.send_raw_transaction(raw)

        receipt = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        )

        # ---- critical fix: mark failure on status=0 (revert/out-of-gas)
        status = int(receipt.status) if hasattr(receipt, "status") else int(receipt.get("status", 0))
        if status != 1:
            log.warning(
                "anchor reverted batch_id=%s tx=%s gasUsed=%s gasLimit=%s status=%s",
                batch_id,
                tx_hash.hex(),
                getattr(receipt, "gasUsed", None),
                gas_limit,
                status,
            )
            return adapter.AnchorResult(error=f"tx reverted: {tx_hash.hex()}")

        block = _w3.eth.get_block(receipt.blockNumber)

        log.info(
            "anchored batch_id=%s tx=%s block=%s gasUsed=%s",
            batch_id,
            tx_hash.hex(),
            receipt.blockNumber,
            getattr(receipt, "gasUsed", None),
        )
        return adapter.AnchorResult(tx_hash=tx_hash.hex(), block_ts=block.timestamp)

    except Exception as exc:
        log.error("Besu anchor failed: %s", exc)
        from . import adapter
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
