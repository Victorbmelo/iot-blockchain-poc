# Off-chain ZKP (ZoKrates) — Logistic Stage Authorization

This folder contains a minimal ZoKrates program that proves a *private* `stage_code` belongs to an authorized set (example set `{0..5}`).
The proof is intended to be **verified off-chain** (in the gateway), while the blockchain remains an immutable audit log.

## Quick start (Windows + Docker)
1. Ensure Docker Desktop is running.
2. From the repo root, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\zkp\setup_zokrates.ps1
```

3. Set in `.env`:
```
ZKP_MODE=zokrates
```

If `ZKP_MODE=policy` (default), the backend enforces a simple whitelist check (NOT zero-knowledge).

## Notes / limitations
- The current circuit has **no public inputs**, so the proof is not cryptographically bound to a specific scan event.
  Binding the proof to an on-chain anchor (e.g., `payloadHash`) is future work and requires a hash-friendly circuit design.
