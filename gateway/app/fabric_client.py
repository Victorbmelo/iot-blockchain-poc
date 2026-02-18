from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("fabric_client")

try:
    from grpc import ssl_channel_credentials, secure_channel
    from hf_fabric_gateway import connect
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False
    log.warning("Fabric Gateway SDK not installed — running in stub mode")

PEER_ENDPOINT = os.getenv("FABRIC_PEER_ENDPOINT", "localhost:7051")
PEER_TLS_CERT = os.getenv("FABRIC_PEER_TLS_CERT", "/certs/peer-tls.pem")
GATEWAY_CERT = os.getenv("FABRIC_GATEWAY_CERT", "/certs/gateway-cert.pem")
GATEWAY_KEY = os.getenv("FABRIC_GATEWAY_KEY", "/certs/gateway-key.pem")
CHANNEL_NAME = os.getenv("FABRIC_CHANNEL", "mychannel")
CHAINCODE_NAME = os.getenv("FABRIC_CHAINCODE", "auditcc")
STUB_MODE = os.getenv("FABRIC_STUB_MODE", "true").lower() == "true"

# In-memory store used exclusively in stub mode.
_stub_store: dict[str, dict] = {}


class FabricClient:
    """Wraps Hyperledger Fabric Gateway calls for the audit layer.

    Falls back to an in-memory stub when FABRIC_STUB_MODE=true or when
    the Fabric SDK is not installed.
    """

    def __init__(self):
        self._stub = STUB_MODE or not SDK_AVAILABLE
        if not self._stub:
            self._connect()
        else:
            log.info("FabricClient running in stub mode")

    def _connect(self):
        tls_cert_path = Path(PEER_TLS_CERT)
        if not tls_cert_path.exists():
            log.warning("TLS cert not found at %s — falling back to stub mode", PEER_TLS_CERT)
            self._stub = True
            return

        tls_cert = tls_cert_path.read_bytes()
        gw_cert = Path(GATEWAY_CERT).read_bytes()
        gw_key = Path(GATEWAY_KEY).read_bytes()

        credentials = ssl_channel_credentials(root_certificates=tls_cert)
        channel = secure_channel(PEER_ENDPOINT, credentials)
        gateway = connect(channel, signer_credentials=(gw_cert, gw_key))
        network = gateway.get_network(CHANNEL_NAME)
        self._contract = network.get_contract(CHAINCODE_NAME)
        log.info("connected to Fabric peer=%s channel=%s chaincode=%s",
                 PEER_ENDPOINT, CHANNEL_NAME, CHAINCODE_NAME)

    def register_event(
        self,
        event_id: str, event_type: str, actor_id: str,
        site_id: str, zone_id: str, ts: str,
        severity: int, source: str,
        payload_hash: str, evidence_ref: str, prev_event_hash: str,
        signature: str, signer_id: str, signer_cert_fingerprint: str,
    ) -> str:
        """Submit RegisterEvent transaction. Returns the transaction ID."""
        args = [
            event_id, event_type, actor_id, site_id, zone_id, ts,
            str(severity), source, payload_hash,
            evidence_ref or "", prev_event_hash or "",
            signature, signer_id, signer_cert_fingerprint,
        ]
        if self._stub:
            return self._stub_register(args)
        result = self._contract.submit("RegisterEvent", arguments=args)
        return result.transaction_id

    def query_event(self, event_id: str) -> dict:
        if self._stub:
            record = _stub_store.get(event_id)
            if not record:
                raise ValueError(f"event {event_id} not found")
            return record
        result = self._contract.evaluate("QueryEvent", arguments=[event_id])
        return json.loads(result)

    def verify_event(self, event_id: str, payload_hash: str) -> str:
        if self._stub:
            return self._stub_verify(event_id, payload_hash)
        result = self._contract.evaluate("VerifyEvent", arguments=[event_id, payload_hash])
        return result.decode("utf-8")

    def get_events_by_actor(self, actor_id: str, from_ts: str, to_ts: str,
                            page_size: int = 50, bookmark: str = "") -> dict:
        if self._stub:
            records = [v for v in _stub_store.values() if v.get("actorId") == actor_id
                       and from_ts <= v.get("ts", "") <= to_ts]
            return {"records": [{"key": r["eventId"], "record": r} for r in records],
                    "fetchedCount": len(records), "bookmark": ""}
        result = self._contract.evaluate("GetEventsByActor",
                                         arguments=[actor_id, from_ts, to_ts,
                                                    str(page_size), bookmark])
        return json.loads(result)

    def get_events_by_zone(self, zone_id: str, from_ts: str, to_ts: str,
                           page_size: int = 50, bookmark: str = "") -> dict:
        if self._stub:
            records = [v for v in _stub_store.values() if v.get("zoneId") == zone_id
                       and from_ts <= v.get("ts", "") <= to_ts]
            return {"records": [{"key": r["eventId"], "record": r} for r in records],
                    "fetchedCount": len(records), "bookmark": ""}
        result = self._contract.evaluate("GetEventsByZone",
                                         arguments=[zone_id, from_ts, to_ts,
                                                    str(page_size), bookmark])
        return json.loads(result)

    def get_events_by_type(self, event_type: str, from_ts: str, to_ts: str,
                           page_size: int = 50, bookmark: str = "") -> dict:
        if self._stub:
            records = [v for v in _stub_store.values() if v.get("eventType") == event_type
                       and from_ts <= v.get("ts", "") <= to_ts]
            return {"records": [{"key": r["eventId"], "record": r} for r in records],
                    "fetchedCount": len(records), "bookmark": ""}
        result = self._contract.evaluate("GetEventsByType",
                                         arguments=[event_type, from_ts, to_ts,
                                                    str(page_size), bookmark])
        return json.loads(result)

    def get_near_misses(self, from_ts: str, to_ts: str,
                        page_size: int = 50, bookmark: str = "") -> dict:
        return self.get_events_by_type("NEAR_MISS", from_ts, to_ts, page_size, bookmark)

    def trace_chain(self, event_id: str) -> list:
        if self._stub:
            return [{"note": "chain tracing requires Fabric mode"}]
        result = self._contract.evaluate("TraceChain", arguments=[event_id])
        return json.loads(result) or []

    def get_audit_package(self, filter_type: str, filter_value: str,
                          from_ts: str = "2000-01-01T00:00:00Z",
                          to_ts: str = "2099-12-31T23:59:59Z") -> dict:
        if self._stub:
            events = list(_stub_store.values())
            pkg_hash = hashlib.sha256(
                json.dumps(events, sort_keys=True).encode()
            ).hexdigest()
            return {
                "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "filter": f"{filter_type}={filter_value}",
                "eventCount": len(events),
                "events": events,
                "packageHash": pkg_hash,
            }
        result = self._contract.evaluate("GetAuditPackage",
                                         arguments=[filter_type, filter_value, from_ts, to_ts])
        return json.loads(result)

    def get_history(self, event_id: str) -> list:
        if self._stub:
            return [{"note": "history not available in stub mode"}]
        result = self._contract.evaluate("GetHistory", arguments=[event_id])
        return json.loads(result) or []

    def query_all(self) -> list[dict]:
        """Return all events from the stub store (stub mode only)."""
        return list(_stub_store.values())

    def _stub_register(self, args: list[str]) -> str:
        event_id = args[0]
        tx_id = f"stub-tx-{hashlib.md5(event_id.encode()).hexdigest()[:12]}"
        _stub_store[event_id] = {
            "schemaVersion": "1.0",
            "eventId": args[0],
            "eventType": args[1],
            "actorId": args[2],
            "siteId": args[3],
            "zoneId": args[4],
            "ts": args[5],
            "tsLedger": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "severity": int(args[6]),
            "source": args[7],
            "payloadHash": args[8],
            "evidenceRef": args[9],
            "prevEventHash": args[10],
            "signature": args[11],
            "signerId": args[12],
            "signerCertFingerprint": args[13],
            "recordedByMSP": "Org1MSP",
            "txId": tx_id,
        }
        return tx_id

    def _stub_verify(self, event_id: str, payload_hash: str) -> str:
        record = _stub_store.get(event_id)
        if not record:
            raise ValueError(f"event {event_id} not found")
        stored = record["payloadHash"]
        if payload_hash == stored:
            return "PASS"
        return f"FAIL: stored={stored} submitted={payload_hash}"


_client: FabricClient | None = None


def get_fabric_client() -> FabricClient:
    global _client
    if _client is None:
        _client = FabricClient()
    return _client
