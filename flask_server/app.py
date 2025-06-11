from flask import Flask, request, jsonify, send_from_directory
from web3 import Web3
import json, os
from dotenv import load_dotenv

QR_DIR = os.path.join(os.path.dirname(__file__), "../frontend/qr_codes")

# 1) Load environment variables from .env
load_dotenv(dotenv_path="../.env", override=True)

app = Flask(__name__, static_folder=None)

# 2) Connect to Ethereum via Ganache
w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL")))
account = w3.eth.account.from_key(os.getenv("PRIVATE_KEY"))
w3.eth.default_account = account.address

# 3) Load contract ABI and address
with open("../build/contract_abi.json") as f:
    abi = json.load(f)
contract_address = os.getenv("CONTRACT_ADDRESS")
# OPTIONAL: you can also read CONTRACT_ADDRESS from file
# contract_address = open("../build/contract_address.txt").read().strip()
contract = w3.eth.contract(address=contract_address, abi=abi)

# Serve the frontend HTML form
@app.route("/")
def home():
    return send_from_directory("../frontend", "index.html")

@app.route("/static/qr_codes/<path:filename>")
def qr_codes(filename):
    return send_from_directory("../frontend/qr_codes", filename)

@app.route("/api/ids", methods=["GET"])
def list_ids():
    # List all .png files, strip extension to get IDs
    files = os.listdir(QR_DIR)
    ids = [os.path.splitext(f)[0] for f in files if f.endswith(".png")]
    return jsonify(ids)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    mat_id   = data.get("id", "")
    location = data.get("location", "Unknown")

    txn = contract.functions.scanMaterial(mat_id, location).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 3000000,
        "gasPrice": w3.to_wei("10", "gwei")
    })
    signed_txn = w3.eth.account.sign_transaction(txn, os.getenv("PRIVATE_KEY"))
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    return jsonify({"status": "success", "tx_hash": receipt.transactionHash.hex()}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
