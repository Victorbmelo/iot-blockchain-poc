import json
import os

from dotenv import load_dotenv
from web3 import Web3

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

load_dotenv(dotenv_path=project_root + r"/.env", override=True)
pk = os.getenv("PRIVATE_KEY")
print(repr(pk), len(pk))

# Load ABI
with open(project_root + r"/build/contract_abi.json", "r") as f:
    abi = json.load(f)

# Load bytecode
with open(project_root + r"/build/contract_bytecode.txt", "r") as f:
    bytecode = f.read().strip()

# Connect to Ganache (or Goerli if you changed RPC_URL)
w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL", "http://127.0.0.1:7545")))

# Use your PRIVATE_KEY from .env
acct = w3.eth.account.from_key(os.getenv("PRIVATE_KEY"))
w3.eth.default_account = acct.address

# Create contract object in Python
MaterialTracker = w3.eth.contract(abi=abi, bytecode=bytecode)

# Deploy the contract
tx_hash = MaterialTracker.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print("Contract deployed to:", tx_receipt.contractAddress)

# Save address for later
with open(project_root + r"/build/contract_address.txt", "w") as f:
    f.write(tx_receipt.contractAddress)
