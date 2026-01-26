import json
import os
import requests
import subprocess
import time

from flask import Flask, request, jsonify, send_from_directory
from web3 import Web3
from dotenv import load_dotenv

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(dotenv_path=os.path.join(project_root, ".env"), override=True)

QR_DIR = os.path.join(project_root, "frontend", "qr_codes")
IPFS_API = os.getenv("IPFS_API", "http://127.0.0.1:5001")
IPFS_GATEWAY = os.getenv("IPFS_GATEWAY", "http://127.0.0.1:8080")

app = Flask(__name__, static_folder=None)

w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL")))
account = w3.eth.account.from_key(os.getenv("PRIVATE_KEY"))
w3.eth.default_account = account.address

# Contract ABI and address
with open(os.path.join(project_root, "build", "contract_abi.json"), encoding="utf-8") as f:
    abi = json.load(f)

_contract_addr = os.getenv("CONTRACT_ADDRESS")
if not _contract_addr:
    raise RuntimeError("CONTRACT_ADDRESS not set in .env")
contract_address = Web3.to_checksum_address(_contract_addr)
contract = w3.eth.contract(address=contract_address, abi=abi)

#region Logistics + off-chain ZKP hooks
#
# Discrete stages to privacy preserving validation.
STAGE_MAP = {
    "RECEIVING": 0,
    "QUALITY_CHECK": 1,
    "INTERNAL_STORAGE": 2,
    "ASSEMBLY_LINE": 3,
    "PACKAGING": 4,
    "SHIPPING": 5,
}
# Stages that are considered "authorized" for anchoring events (example policy).
AUTHORIZED_STAGES = set(STAGE_MAP.keys())

# ZKP mode:
# none: no proof, only store stage in payload
# policy: simple whitelist validation (NOT zero-knowledge; baseline enforcement)
# zokrates: attempts Groth16 proof generation/verification via ZoKrates in Docker (off-chain)
ZKP_MODE = os.getenv("ZKP_MODE", "policy").strip().lower()

# ZoKrates folder (expects zkp/setup_zokrates))
ZKP_DIR = os.path.join(project_root, "zkp")
ZOKRATES_IMAGE = os.getenv("ZOKRATES_IMAGE", "zokrates/zokrates:latest")

def _stage_normalize(s: str) -> str:
    return (s or "").strip().upper().replace(" ", "_")

def _zkp_policy_verify(stage: str) -> dict:
    """Policy check (not ZK)."""
    st = _stage_normalize(stage)
    ok = st in AUTHORIZED_STAGES
    return {"mode": "policy", "verified": ok, "stage": st}

def _zokrates_available() -> bool:
    # Docker availability is checked at runtime.
    return os.path.isfile(os.path.join(ZKP_DIR, "out")) and os.path.isfile(os.path.join(ZKP_DIR, "proving.key")) and os.path.isfile(os.path.join(ZKP_DIR, "verification.key"))

def _run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def _zkp_zokrates_prove_and_verify(stage: str) -> dict:
    """
    Provides a ZK proof only if the ZoKrates were generated beforehand.
    If anything fails, caller should fallback to policy mode.
    """
    st = _stage_normalize(stage)
    if st not in STAGE_MAP:
        return {"mode": "zokrates", "verified": False, "error": "unknown_stage", "stage": st}
    if not _zokrates_available():
        return {"mode": "zokrates", "verified": False, "error": "zokrates_artifacts_missing", "stage": st}

    stage_code = STAGE_MAP[st]
    try:
        # compute witness
        r1 = _run(["docker", "run", "--rm",
                   "-v", f"{ZKP_DIR}:/home/zokrates/work",
                   "-w", "/home/zokrates/work",
                   ZOKRATES_IMAGE, "zokrates", "compute-witness", "-a", str(stage_code)], timeout=60)
        if r1.returncode != 0:
            return {"mode": "zokrates", "verified": False, "error": "compute_witness_failed", "stderr": r1.stderr[:4000], "stage": st}

        r2 = _run(["docker", "run", "--rm",
                   "-v", f"{ZKP_DIR}:/home/zokrates/work",
                   "-w", "/home/zokrates/work",
                   ZOKRATES_IMAGE, "zokrates", "generate-proof"], timeout=120)
        if r2.returncode != 0:
            return {"mode": "zokrates", "verified": False, "error": "generate_proof_failed", "stderr": r2.stderr[:4000], "stage": st}

        r3 = _run(["docker", "run", "--rm",
                   "-v", f"{ZKP_DIR}:/home/zokrates/work",
                   "-w", "/home/zokrates/work",
                   ZOKRATES_IMAGE, "zokrates", "verify"], timeout=60)
        ok = (r3.returncode == 0) and ("PASSED" in (r3.stdout + r3.stderr))
        return {"mode": "zokrates", "verified": bool(ok), "stage": st}
    except Exception as e:
        return {"mode": "zokrates", "verified": False, "error": str(e), "stage": st}
#endregion


#region IPFS helpers
def ipfs_add_json(payload: dict) -> str:
    """Add JSON payload to IPFS via Kubo HTTP API (/api/v0/add). Returns CID."""
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    files = {"file": ("payload.json", data)}
    r = requests.post(f"{IPFS_API}/api/v0/add", files=files, timeout=15)
    r.raise_for_status()
    return r.json()["Hash"]  # CID


def ipfs_get_json(cid: str):
    """Fetch JSON payload from IPFS gateway. Returns dict or None."""
    try:
        r = requests.get(f"{IPFS_GATEWAY}/ipfs/{cid}", timeout=10)
        if not r.ok:
            return None
        return r.json()
    except Exception:
        return None
#endregion


#region API Endpoints
# Serve the frontend HTML form
@app.route("/")
def home():
    return send_from_directory(os.path.join(project_root, "frontend"), "index.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(project_root, "frontend"), filename)


@app.route("/static/qr_codes/<path:filename>")
def qr_codes(filename):
    return send_from_directory(os.path.join(project_root, "frontend", "qr_codes"), filename)


@app.route("/api/ids", methods=["GET"])
def list_ids():
    # List all .png files, strip extension to get IDs
    try:
        files = os.listdir(QR_DIR)
    except FileNotFoundError:
        files = []
    ids = [os.path.splitext(f)[0] for f in files if f.endswith(".png")]
    ids.sort()
    return jsonify(ids)



@app.route("/api/stages", methods=["GET"])
def list_stages():
    """Return known logistic stages for the UI."""
    return jsonify(sorted(list(STAGE_MAP.keys())) + ["UNKNOWN"])


@app.route("/zkp/status", methods=["GET"])
def zkp_status():
    """Health/info endpoint for the ZKP subsystem (off-chain)."""
    return jsonify({
        "zkp_mode": ZKP_MODE,
        "authorized_stages": sorted(list(AUTHORIZED_STAGES)),
        "zokrates_artifacts_ready": bool(_zokrates_available()) if ZKP_MODE == "zokrates" else False
    })

def _parse_bool(v: str, default: bool = True) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


@app.route("/history", methods=["GET"])
def history_query():
    """Get scan history. Optional query params:
    - id: filter by material id (uses indexed event filter)
    - include_payload: true/false (default true)
    - from_block: int (default 0)
    - to_block: int or 'latest' (default latest)
    """
    mat_id = request.args.get("materialId") or request.args.get("id")
    include_payload = _parse_bool(request.args.get("include_payload", None), default=True)

    from_block = request.args.get("from_block", 0)
    try:
        from_block = int(from_block)
        if from_block < 0:
            from_block = 0
    except ValueError:
        from_block = 0

    to_block = request.args.get("to_block", "latest")
    if to_block != "latest":
        try:
            to_block = int(to_block)
        except ValueError:
            to_block = "latest"

    if mat_id:
        material_id_hash = Web3.keccak(text=mat_id)
        logs = contract.events.MaterialScanned.get_logs(
            from_block=from_block,
            to_block=to_block,
            argument_filters={"materialIdHash": material_id_hash}
        )
    else:
        logs = contract.events.MaterialScanned.get_logs(from_block=from_block, to_block=to_block)

    out = []
    for e in logs:
        args = e["args"]
        cid = args.get("cid")
        payload = None

        if include_payload and cid:
            try:
                payload = ipfs_get_json(cid)
            except Exception:
                payload = None

        out.append({
            "tx_hash": e["transactionHash"].hex(),
            "block_number": e["blockNumber"],
            "scanner": args.get("scanner"),
            "timestamp": args.get("timestamp"),
            "materialId": args.get("materialId"),
            "materialIdHash": args.get("materialIdHash").hex() if args.get("materialIdHash") is not None else None,
            "cid": cid,
            "payload_hash": args.get("payloadHash").hex() if args.get("payloadHash") is not None else None,
            "payload": payload
        })

    out.sort(key=lambda x: (x["block_number"], x["tx_hash"]))

    return jsonify({
        "query": {
            "materialId": mat_id,
            "include_payload": include_payload,
            "from_block": from_block,
            "to_block": to_block
        },
        "count": len(out),
        "events": out
    })


#region Integrity verification
def _get_scan_event_by_tx_hash(tx_hash_hex: str):
    """Return decoded MaterialScanned event + receipt for a given tx hash (hex string)."""
    txh = (tx_hash_hex or "").strip()
    if txh.startswith("0x"):
        txh = txh
    else:
        txh = "0x" + txh
    receipt = w3.eth.get_transaction_receipt(txh)
    decoded = contract.events.MaterialScanned().process_receipt(receipt)
    if not decoded:
        return None, receipt
    # Expect exactly one scan event in the tx; pick the first
    return decoded[0], receipt


def _latest_event_for_material(material_id: str):
    """Fetch latest MaterialScanned event for a materialId using the indexed hash filter."""
    mid = (material_id or "").strip()
    if not mid:
        return None
    h = Web3.keccak(text=mid)
    logs = contract.events.MaterialScanned.get_logs(from_block=0, to_block="latest", argument_filters={"materialIdHash": h})
    if not logs:
        return None
    # logs are ordered by blockNumber/transactionIndex/logIndex
    logs.sort(key=lambda e: (e["blockNumber"], e["transactionIndex"], e["logIndex"]))
    return logs[-1]


@app.route("/verify", methods=["GET"])
def verify_integrity():
    """Verify that the IPFS payload matches the on-chain anchor.

    Query params (one of tx_hash or materialId is recommended):
    - tx_hash: transaction hash containing a MaterialScanned event
    - materialId: verify latest event for this materialId (uses indexed filter)
    - cid: optional override (otherwise taken from the event)
    - include_payload: true/false (default true) include payload in response
    """
    tx_hash = request.args.get("tx_hash")
    material_id = request.args.get("materialId") or request.args.get("id")
    cid_override = request.args.get("cid")
    include_payload = _parse_bool(request.args.get("include_payload", None), default=True)

    ev = None
    receipt = None

    try:
        if tx_hash:
            ev, receipt = _get_scan_event_by_tx_hash(tx_hash)
            if ev is None:
                return jsonify({"status": "error", "message": "No MaterialScanned event found in tx", "tx_hash": tx_hash}), 404
            args = ev["args"]
            anchored_hash = args.get("payloadHash")
            cid = cid_override or args.get("cid")
            material_id_res = args.get("materialId")

        else:
            # fallback: latest event for a materialId
            if not material_id:
                return jsonify({"status": "error", "message": "Provide tx_hash or materialId"}), 400

            log = _latest_event_for_material(material_id)
            if log is None:
                return jsonify({"status": "error", "message": "No events found for materialId", "materialId": material_id}), 404

            args = log["args"]
            anchored_hash = args.get("payloadHash")
            cid = cid_override or args.get("cid")
            material_id_res = args.get("materialId")

        if not cid:
            return jsonify({"status": "error", "message": "CID missing (event has no cid and none provided)"}), 400

        # Fetch payload from IPFS gateway
        payload = ipfs_get_json(cid)
        payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        computed_hash = Web3.keccak(payload_bytes)

        ok = (anchored_hash == computed_hash)

        resp = {
            "status": "success",
            "verified": bool(ok),
            "materialId": material_id_res,
            "cid": cid,
            "anchored_payload_hash": anchored_hash.hex() if anchored_hash is not None else None,
            "computed_payload_hash": computed_hash.hex(),
        }

        if tx_hash:
            resp["tx_hash"] = receipt["transactionHash"].hex() if receipt else tx_hash

        if include_payload:
            resp["payload"] = payload

        if not ok:
            resp["message"] = "Hash mismatch: payload does not match on-chain anchor"

        return jsonify(resp), 200

    except Exception as e:
        return jsonify({"status": "error", "message": "Verification failed", "error": str(e)}), 500
#endregion


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    mat_id = (data.get("materialId") or data.get("id") or "").strip()
    location = (data.get("location") or "Unknown").strip()
    stage = (data.get("logisticStage") or data.get("stage") or "RECEIVING").strip()

    if not mat_id:
        return jsonify({"status": "error", "message": "materialId is required"}), 400

    # Off chain validation / ZKP hook
    if ZKP_MODE == "zokrates":
        zkp_res = _zkp_zokrates_prove_and_verify(stage)
        if (not zkp_res.get("verified", False)) and zkp_res.get("error") in ("zokrates_artifacts_missing",):
            # fallback to policy if artifacts not ready
            zkp_res = _zkp_policy_verify(stage)
    elif ZKP_MODE == "none":
        zkp_res = {"mode": "none", "verified": True, "stage": _stage_normalize(stage)}
    else:
        zkp_res = _zkp_policy_verify(stage)

    if not zkp_res.get("verified", False):
        return jsonify({"status": "error", "message": "Unauthorized logistic stage", "details": zkp_res}), 403

    payload = {
        "materialId": mat_id,
        "location": location,
        "logisticStage": zkp_res.get("stage"),
        "client_ts": int(time.time()),
        "zkp": {"mode": zkp_res.get("mode"), "verified": True}
    }

    cid = ipfs_add_json(payload)

    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_hash = Web3.keccak(payload_bytes)  # bytes32

    txn = contract.functions.scanMaterial(mat_id, cid, payload_hash).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 3000000,
        "gasPrice": w3.to_wei("10", "gwei"),
        "chainId": w3.eth.chain_id,
    })

    signed_txn = w3.eth.account.sign_transaction(txn, os.getenv("PRIVATE_KEY"))
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    return jsonify({
        "status": "success",
        "tx_hash": receipt.transactionHash.hex(),
        "cid": cid,
        "payload_hash": payload_hash.hex(),
        "materialId": mat_id,
        "logisticStage": zkp_res.get("stage"),
        "zkp": {"mode": zkp_res.get("mode"), "verified": True}
    }), 200
#endregion

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
