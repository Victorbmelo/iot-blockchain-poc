#!/usr/bin/env python3
"""Unit tests for core logic (no Docker, no Postgres, no Besu needed)."""
import hashlib, json, sys, unicodedata
sys.path.insert(0, 'services/audit-gateway')
from app.merkle import compute_root, compute_proof, verify_proof

def test_merkle_canonical():
    h = ["a"*64, "b"*64, "c"*64, "d"*64]
    assert compute_root(h) == compute_root(list(reversed(h)))

def test_merkle_tamper():
    h = ["a"*64, "b"*64, "c"*64]
    root = compute_root(h)
    tampered = ["a"*64, "b"*64, "0"*64]
    assert compute_root(tampered) != root

def test_merkle_deletion():
    h = ["a"*64, "b"*64, "c"*64]
    assert compute_root(h) != compute_root(h[1:])

def test_merkle_injection():
    h = ["a"*64, "b"*64]
    assert compute_root(h) != compute_root(h + ["c"*64])

def test_merkle_proof():
    h = ["a"*64, "b"*64, "c"*64, "d"*64]
    root = compute_root(h)
    proof = compute_proof(h, "a"*64)
    assert proof is not None
    assert verify_proof("a"*64, proof, root)

def test_merkle_proof_wrong_hash():
    h = ["a"*64, "b"*64, "c"*64]
    root = compute_root(h)
    proof = compute_proof(h, "a"*64)
    assert not verify_proof("0"*64, proof, root)

CANONICAL_FIELDS = ["schema_version", "event_type", "ts", "site_id",
                    "zone_id", "actor_id", "severity", "source", "payload"]
def event_hash(ev):
    def sk(o):
        if isinstance(o, dict): return {k: sk(o[k]) for k in sorted(o)}
        if isinstance(o, list): return [sk(v) for v in o]
        return o
    sub = {k: ev.get(k) for k in CANONICAL_FIELDS if ev.get(k) is not None}
    sub["schema_version"] = "1.0"
    r = json.dumps(sk(sub), separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(unicodedata.normalize("NFC", r).encode()).hexdigest()

BASE = {"event_type":"NEAR_MISS","ts":"2024-01-01T00:00:00Z","site_id":"s1",
        "zone_id":"Z04","actor_id":"W001","severity":4,"source":"camera","payload":{"x":1}}

def test_hash_deterministic():
    assert event_hash(BASE) == event_hash(dict(BASE))

def test_hash_tamper_severity():
    t = dict(BASE); t["severity"] = 1
    assert event_hash(BASE) != event_hash(t)

def test_hash_tamper_payload():
    t = dict(BASE); t["payload"] = {"x": 99}
    assert event_hash(BASE) != event_hash(t)

def test_hash_canonical_key_order():
    reordered = {"source":"camera","actor_id":"W001","event_type":"NEAR_MISS",
                 "ts":"2024-01-01T00:00:00Z","site_id":"s1","zone_id":"Z04",
                 "severity":4,"payload":{"x":1}}
    assert event_hash(BASE) == event_hash(reordered)

def test_hash_nonce_excluded():
    with_nonce = dict(BASE); with_nonce["nonce"] = "abc"
    assert event_hash(BASE) == event_hash(with_nonce)

def test_hash_evidence_ref_excluded():
    with_ref = dict(BASE); with_ref["evidence_ref"] = "s3://x"
    assert event_hash(BASE) == event_hash(with_ref)

if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t(); passed += 1; print(f"  PASS  {t.__name__}")
        except Exception as exc:
            failed += 1; print(f"  FAIL  {t.__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
