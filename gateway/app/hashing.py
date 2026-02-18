import hashlib
import json
from datetime import datetime, timezone


def compute_payload_hash(payload: dict) -> str:
    """Return the SHA-256 hex digest of the canonical JSON representation of a payload dict."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_string_hash(data: str) -> str:
    """Return the SHA-256 hex digest of a raw string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_event_id(site_id: str, actor_id: str, ts_event: str, event_type: str) -> str:
    """Return a deterministic event ID derived from the event's identifying fields."""
    seed = f"{site_id}:{actor_id}:{ts_event}:{event_type}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    return f"evt-{digest}"


def build_canonical_payload(event_data: dict) -> dict:
    """Return the subset of event fields used for hashing.

    Only stable, identifying fields are included. Fields like evidence_uri
    are excluded because they may be populated asynchronously.
    """
    included_keys = [
        "event_type", "ts_event", "site_id", "zone_id",
        "actor_id", "severity", "source", "payload_extra",
    ]
    return {k: event_data[k] for k in included_keys if event_data.get(k) is not None}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
