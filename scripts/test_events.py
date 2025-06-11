from web3 import Web3
import json, os
from dotenv import load_dotenv
from datetime import datetime

# 1) Load environment variables
load_dotenv(dotenv_path="../.env", override=True)

# 2) Connect to Ganache (or Goerli)
w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL", "http://127.0.0.1:7545")))

# 3) Load ABI and contract
with open("../build/contract_abi.json", "r") as f:
    abi = json.load(f)

contract_address = os.getenv("CONTRACT_ADDRESS")
contract = w3.eth.contract(address=contract_address, abi=abi)

# 4) Create a filter for MaterialScanned events from block 0
event_filter = contract.events.MaterialScanned.create_filter(from_block=0)

# 5) Get all matching entries
events = event_filter.get_all_entries()

# 6) Print each event’s args, converting timestamp to datetime
for ev in events:
    raw_ts = ev["args"]["timestamp"]  # This is an integer (seconds since epoch)
    dt = datetime.fromtimestamp(raw_ts)  # Convert to datetime object

    print("ID:       ", ev["args"]["id"])
    print("Scanner:  ", ev["args"]["scanner"])
    print("Timestamp:", raw_ts, "→", dt.strftime("%Y-%m-%d %H:%M:%S"))
    print("Location: ", ev["args"]["location"])
    print("-" * 40)
