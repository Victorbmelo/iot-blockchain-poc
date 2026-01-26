import json
import os

from solcx import compile_source, install_solc

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Version of solc
install_solc("0.8.0")

with open(project_root + r"/contracts/MaterialTracker.sol", "r") as f:
    source = f.read()

compiled_sol = compile_source(
    source,
    output_values=["abi", "bin"],     # <- ask for ABI and bytecode
    solc_version="0.8.0"
)

# compiled_sol is a dict with keys "<stdin>:MaterialTracker"
contract_id, contract_interface = compiled_sol.popitem()

abi = contract_interface["abi"]
bytecode = contract_interface["bin"]

# Save ABI to a JSON file
os.makedirs(project_root + r"/build", exist_ok=True)

with open(project_root + r"/build/contract_abi.json", "w") as f:
    json.dump(abi, f, indent=4)

# Optionally save bytecode somewhere
with open(project_root + r"/build/contract_bytecode.txt", "w") as f:
    f.write(bytecode)

print("Compilation successful. ABI and bytecode have been written.")
