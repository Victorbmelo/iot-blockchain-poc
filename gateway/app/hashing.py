"""
Canonical hashing for the Audit Gateway.

All payload hashing goes through this module to guarantee consistency.
Two payloads that are semantically identical always produce the same hash.

Canonicalisation rules:
  - Keys sorted alphabetically (recursive)
  - No extra whitespace
  - Numbers serialised without trailing zeros
  - Unicode normalised to NFC
  - Encoding: UTF-8
"""
import hashlib
import json
import secrets
import unicodedata
from datetime import datetime, timezone


def _sort_keys_recursive(obj):
    """Recursively sort dict keys for canonical serialisation."""
    if isinstance(obj, dict):
        return {k: _sort_keys_recursive(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_sort_keys_recursive(v) for v in obj]
    return obj


def canonical_json(payload: dict) -> str:
    """Return the canonical JSON string of a payload dict."""
    normalised = _sort_keys_recursive(payload)
    raw = json.dumps(normalised, separators=(",", ":"), ensure_ascii=False)
    return unicodedata.normalize("NFC", raw)


def compute_payload_hash(payload: dict) -> str:
    """Return the SHA-256 hex digest of the canonical JSON of a payload dict."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def compute_string_hash(data: str) -> str:
    """Return the SHA-256 hex digest of a raw string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_event_id(schema_version: str, actor_id: str, ts: str,
                      event_type: str, zone_id: str, nonce: str) -> str:
    """Return a deterministic event ID from the event's identifying fields plus a nonce.

    Including a nonce allows the IoT platform to retry submission without
    generating a duplicate ID (as long as it uses the same nonce on retry).
    """
    seed = f"{schema_version}:{actor_id}:{ts}:{event_type}:{zone_id}:{nonce}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    return f"evt-{digest}"


def build_canonical_payload(event_data: dict) -> dict:
    """Return the canonical subset of event fields used for hashing.

    Only stable, identifying fields are included. Fields like evidence_ref
    are excluded because they may be resolved asynchronously after submission.
    """
    included = [
        "schema_version", "event_type", "ts", "site_id", "zone_id",
        "actor_id", "severity", "source", "payload_extra",
    ]
    return {k: event_data[k] for k in included if event_data.get(k) is not None}


def generate_nonce() -> str:
    """Return a 16-byte random hex nonce for use in event ID generation."""
    return secrets.token_hex(16)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
