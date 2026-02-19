#!/usr/bin/env python3
"""
Deploy AuditAnchor.sol to the Besu network.
Compiles the contract, deploys, saves address + ABI to contracts/deployed.json.

Usage:
    python contracts/deploy.py
    # or via Makefile: make deploy-contract
"""
import json
import os
import subprocess
import sys
from pathlib import Path
from web3 import Web3
from web3.middleware import geth_poa_middleware

BESU_RPC = os.getenv("BESU_RPC", "http://localhost:8545")
PRIVATE_KEY = os.getenv(
    "GATEWAY_PRIVATE_KEY",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # Besu dev account
)
CONTRACT_DIR = Path(__file__).parent

def compile_contract():
    """Compile using solc from PATH, or fall back to py-solc-x."""
    sol_file = CONTRACT_DIR / "AuditAnchor.sol"
    try:
        # Try system solc first
        result = subprocess.run(
            ["solc", "--combined-json", "abi,bin", "--optimize", str(sol_file)],
            capture_output=True, text=True, check=True,
        )
        data = json.loads(result.stdout)
        key = "AuditAnchor.sol:AuditAnchor"
        contract_data = data["contracts"][key]
        return contract_data["abi"], contract_data["bin"]
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError):
        pass

    # Fall back to py-solc-x
    try:
        from solcx import compile_source, install_solc
        install_solc("0.8.19", show_progress=False)
        compiled = compile_source(
            sol_file.read_text(),
            output_values=["abi", "bin"],
            solc_version="0.8.19",
            optimize=True,
        )
        key = next(k for k in compiled if "AuditAnchor" in k)
        return compiled[key]["abi"], compiled[key]["bin"]
    except Exception as exc:
        raise RuntimeError(
            f"Could not compile contract. Install solc or py-solc-x: {exc}"
        ) from exc


def deploy():
    print(f"Connecting to Besu at {BESU_RPC} ...")
    w3 = Web3(Web3.HTTPProvider(BESU_RPC))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    for _ in range(30):
        if w3.is_connected():
            break
        import time; time.sleep(1)
    else:
        sys.exit(f"Cannot connect to Besu at {BESU_RPC}")

    account = w3.eth.account.from_key(PRIVATE_KEY)
    print(f"Deploying from account: {account.address}")
    print(f"Account balance: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")

    print("Compiling AuditAnchor.sol ...")
    abi, bytecode = compile_contract()

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor().build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 2_000_000,
        "gasPrice": 0,
    })

    signed = account.sign_transaction(tx)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction")
    tx_hash = w3.eth.send_raw_transaction(raw)
    print(f"Deploy tx: {tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    address = receipt.contractAddress
    print(f"Contract deployed at: {address}")

    deployed = {"address": address, "abi": abi, "tx_hash": tx_hash.hex()}
    out_path = CONTRACT_DIR / "deployed.json"
    out_path.write_text(json.dumps(deployed, indent=2))
    print(f"Saved to: {out_path}")
    return address


if __name__ == "__main__":
    deploy()
