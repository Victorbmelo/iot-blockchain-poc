# Setup ZoKrates artifacts (compile + setup + export keys) using Docker.
# Run from repo root:
#   powershell -ExecutionPolicy Bypass -File .\zkp\setup_zokrates.ps1

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Resolve-Path (Join-Path $here ".")
Write-Host "Using ZKP workdir: $work"

# Zokrates CLI is 'zokrates', not 'compile/setup'
docker run --rm -v "${work}:/home/zokrates/work" -w /home/zokrates/work zokrates/zokrates:latest zokrates compile -i stage_in_whitelist.zok
docker run --rm -v "${work}:/home/zokrates/work" -w /home/zokrates/work zokrates/zokrates:latest zokrates setup
docker run --rm -v "${work}:/home/zokrates/work" -w /home/zokrates/work zokrates/zokrates:latest zokrates export-verifier

Write-Host "Done. Check zkp/ for: out, proving.key, verification.key, verifier.sol"
