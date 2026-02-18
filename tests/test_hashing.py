"""
Unit tests for the hashing module.

Tests canonical JSON determinism, hash consistency, and event ID generation.
Run with: pytest tests/
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gateway.app.hashing import (
    canonical_json, compute_payload_hash, compute_string_hash,
    generate_event_id, build_canonical_payload,
)


def test_canonical_json_is_deterministic():
    p1 = {"b": 2, "a": 1, "c": {"z": 26, "y": 25}}
    p2 = {"c": {"y": 25, "z": 26}, "a": 1, "b": 2}
    assert canonical_json(p1) == canonical_json(p2)


def test_canonical_json_sorts_keys():
    result = canonical_json({"z": 1, "a": 2})
    assert result.index('"a"') < result.index('"z"')


def test_payload_hash_is_consistent():
    payload = {"event_type": "NEAR_MISS", "actor_id": "W001", "severity": 4}
    assert compute_payload_hash(payload) == compute_payload_hash(payload)
    assert len(compute_payload_hash(payload)) == 64


def test_payload_hash_changes_on_mutation():
    base = {"event_type": "NEAR_MISS", "severity": 4}
    modified = {"event_type": "NEAR_MISS", "severity": 1}
    assert compute_payload_hash(base) != compute_payload_hash(modified)


def test_event_id_deterministic_with_same_nonce():
    args = ("1.0", "W001", "2024-11-15T09:00:00+00:00", "NEAR_MISS", "Z04", "fixed-nonce")
    assert generate_event_id(*args) == generate_event_id(*args)
    assert generate_event_id(*args).startswith("evt-")


def test_event_id_differs_on_different_nonce():
    base = ("1.0", "W001", "2024-11-15T09:00:00+00:00", "NEAR_MISS", "Z04")
    assert generate_event_id(*base, "nonce1") != generate_event_id(*base, "nonce2")


def test_canonical_payload_excludes_non_hashable_fields():
    data = {
        "schema_version": "1.0",
        "event_type": "NEAR_MISS",
        "ts": "2024-11-15T09:00:00+00:00",
        "site_id": "site-01",
        "zone_id": "Z04",
        "actor_id": "W001",
        "severity": 4,
        "source": "wearable",
        "payload_extra": None,
        "evidence_ref": "minio://bucket/file.json",
        "prev_event_hash": "",
    }
    canonical = build_canonical_payload(data)
    assert "evidence_ref" not in canonical
    assert "prev_event_hash" not in canonical
    assert canonical["event_type"] == "NEAR_MISS"


def test_string_hash_matches_sha256():
    import hashlib
    data = "hello audit layer"
    expected = hashlib.sha256(data.encode()).hexdigest()
    assert compute_string_hash(data) == expected
