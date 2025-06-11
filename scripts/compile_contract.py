from solcx import compile_source, install_solc
import json

# 1) Ensure the exact version of solc you need is installed
install_solc("0.8.0")

# 2) Load your Solidity source
with open("../contracts/MaterialTracker.sol", "r") as f:
    source = f.read()

# 3) Compile the contract source
compiled_sol = compile_source(
    source,
    output_values=["abi", "bin"],     # <- explicitly ask for ABI and bytecode
    solc_version="0.8.0"
)

# compiled_sol is a dict with keys "<stdin>:MaterialTracker"
contract_id, contract_interface = compiled_sol.popitem()

abi = contract_interface["abi"]
bytecode = contract_interface["bin"]

# 4) Save ABI to a JSON file
with open("../build/contract_abi.json", "w") as f:
    json.dump(abi, f)

# 5) Optionally save bytecode somewhere
with open("../build/contract_bytecode.txt", "w") as f:
    f.write(bytecode)

print("Compilation successful. ABI and bytecode have been written.")
