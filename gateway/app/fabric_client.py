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
    the Fabric SDK is not installed, allowing local development without
    a running Fabric network.
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
        log.info("connected to Fabric peer=%s channel=%s chaincode=%s", PEER_ENDPOINT, CHANNEL_NAME, CHAINCODE_NAME)

    def register_event(
        self,
        event_id: str, event_type: str, ts_event: str,
        site_id: str, zone_id: str, actor_id: str,
        severity: str, source: str,
        payload_hash: str, evidence_uri: str, prev_event_hash: str,
    ) -> str:
        """Submit a RegisterEvent transaction. Returns the transaction ID."""
        args = [
            event_id, event_type, ts_event, site_id, zone_id,
            actor_id, severity, source, payload_hash,
            evidence_uri or "", prev_event_hash or "",
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

    def verify_integrity(self, event_id: str, payload_json: str) -> str:
        if self._stub:
            return self._stub_verify(event_id, payload_json)
        result = self._contract.evaluate("VerifyIntegrity", arguments=[event_id, payload_json])
        return result.decode("utf-8")

    def query_by_worker(self, actor_id: str) -> list[dict]:
        if self._stub:
            return [v for v in _stub_store.values() if v.get("actor_id") == actor_id]
        return self._evaluate_list("QueryByWorker", [actor_id])

    def query_by_zone(self, zone_id: str) -> list[dict]:
        if self._stub:
            return [v for v in _stub_store.values() if v.get("zone_id") == zone_id]
        return self._evaluate_list("QueryByZone", [zone_id])

    def query_by_event_type(self, event_type: str) -> list[dict]:
        if self._stub:
            return [v for v in _stub_store.values() if v.get("event_type") == event_type]
        return self._evaluate_list("QueryByEventType", [event_type])

    def query_by_severity(self, severity: str) -> list[dict]:
        if self._stub:
            return [v for v in _stub_store.values() if v.get("severity") == severity]
        return self._evaluate_list("QueryBySeverity", [severity])

    def query_by_time_range(self, start_ts: str, end_ts: str) -> list[dict]:
        if self._stub:
            return [v for v in _stub_store.values() if start_ts <= v.get("ts_event", "") <= end_ts]
        return self._evaluate_list("QueryByTimeRange", [start_ts, end_ts])

    def get_audit_package(self, filter_type: str, filter_value: str) -> dict:
        if self._stub:
            events = list(_stub_store.values())
            pkg_hash = hashlib.sha256(
                json.dumps(events, sort_keys=True).encode()
            ).hexdigest()
            return {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "filter": f"{filter_type}={filter_value}",
                "event_count": len(events),
                "events": events,
                "package_hash": pkg_hash,
            }
        result = self._contract.evaluate("GetAuditPackage", arguments=[filter_type, filter_value])
        return json.loads(result)

    def get_history(self, event_id: str) -> list[dict]:
        if self._stub:
            return [{"note": "history not available in stub mode"}]
        result = self._contract.evaluate("GetHistory", arguments=[event_id])
        return json.loads(result) or []

    def _evaluate_list(self, function_name: str, args: list[str]) -> list[dict]:
        result = self._contract.evaluate(function_name, arguments=args)
        return json.loads(result) or []

    def _stub_register(self, args: list[str]) -> str:
        event_id = args[0]
        tx_id = f"stub-tx-{hashlib.md5(event_id.encode()).hexdigest()[:12]}"
        _stub_store[event_id] = {
            "event_id": args[0],
            "event_type": args[1],
            "ts_event": args[2],
            "site_id": args[3],
            "zone_id": args[4],
            "actor_id": args[5],
            "severity": args[6],
            "source": args[7],
            "payload_hash": args[8],
            "evidence_uri": args[9],
            "prev_event_hash": args[10],
            "tx_id": tx_id,
            "ts_ingest": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "recorded_by": "Org1MSP",
        }
        return tx_id

    def _stub_verify(self, event_id: str, payload_json: str) -> str:
        record = _stub_store.get(event_id)
        if not record:
            raise ValueError(f"event {event_id} not found")
        stored_hash = record["payload_hash"]
        computed = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        if computed == stored_hash:
            return "PASS"
        return f"FAIL: stored={stored_hash} computed={computed}"


_client: FabricClient | None = None


def get_fabric_client() -> FabricClient:
    global _client
    if _client is None:
        _client = FabricClient()
    return _client
