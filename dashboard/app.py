"""
Audit Layer Dashboard — Streamlit

Shows a live event timeline, integrity verification, chain tracing,
and runtime metrics. The "Simulate Tampering" button demonstrates
tamper detection in the UI without any manual CLI steps.

Run:
    streamlit run dashboard/app.py
"""
import hashlib
import json
import time
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

GATEWAY = st.sidebar.text_input("Gateway URL", value="http://localhost:8080")

st.set_page_config(
    page_title="Audit Layer — Construction Site Safety",
    layout="wide",
)

st.title("Immutable Audit Layer")
st.caption("Politecnico di Torino — IoT Safety Data in Construction Sites")


def api(path: str, method: str = "GET", **kwargs):
    try:
        resp = requests.request(method, f"{GATEWAY}{path}", timeout=8, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        st.error(f"Gateway error: {exc}")
        return None


# Sidebar — health
with st.sidebar:
    st.subheader("Gateway Status")
    health = api("/health")
    if health:
        st.success("Connected")
        st.json({
            "stub_mode": health.get("stub_mode"),
            "schema_version": health.get("schema_version"),
            "signer_id": health.get("signer_id"),
        })
    else:
        st.error("Gateway unreachable")
    st.caption(f"Refreshed at {datetime.now().strftime('%H:%M:%S')}")

tab_timeline, tab_verify, tab_metrics, tab_tamper = st.tabs([
    "Event Timeline", "Verify Integrity", "Metrics", "Simulate Tampering"
])


# --- Tab 1: Event Timeline ---
with tab_timeline:
    st.subheader("Event Timeline")

    col1, col2, col3 = st.columns(3)
    filter_by = col1.selectbox("Filter by", ["all", "zone", "actor", "event_type"])
    filter_val = col2.text_input("Value", placeholder="e.g. Z04 / W001 / NEAR_MISS")
    page_size = col3.slider("Page size", 10, 200, 50)

    if st.button("Load Events"):
        with st.spinner("Fetching events..."):
            if filter_by == "zone" and filter_val:
                data = api(f"/zones/{filter_val}/events?page_size={page_size}")
            elif filter_by == "actor" and filter_val:
                data = api(f"/actors/{filter_val}/events?page_size={page_size}")
            elif filter_by == "event_type" and filter_val:
                data = api(f"/events?event_type={filter_val}&page_size={page_size}")
            else:
                data = api("/events")

        if data:
            records = data if isinstance(data, list) else data.get("records", [])
            events = [r.get("record", r) for r in records]

            if events:
                df = pd.DataFrame(events)
                for col in ["ts", "tsLedger"]:
                    if col in df.columns:
                        df[col] = pd.to_datetime(df[col], errors="coerce")

                st.metric("Events loaded", len(df))

                if "ts" in df.columns and "eventType" in df.columns:
                    fig = px.scatter(
                        df,
                        x="ts",
                        y="eventType",
                        color="severity",
                        hover_data=["actorId", "zoneId", "source"],
                        title="Event Timeline",
                        color_continuous_scale="RdYlGn_r",
                    )
                    st.plotly_chart(fig, use_container_width=True)

                if "severity" in df.columns:
                    col_a, col_b = st.columns(2)
                    with col_a:
                        fig2 = px.histogram(df, x="eventType", title="Events by Type")
                        st.plotly_chart(fig2, use_container_width=True)
                    with col_b:
                        fig3 = px.histogram(df, x="severity", title="Events by Severity")
                        st.plotly_chart(fig3, use_container_width=True)

                st.dataframe(df, use_container_width=True)
            else:
                st.info("No events found for this filter.")


# --- Tab 2: Integrity Verification ---
with tab_verify:
    st.subheader("Integrity Verification")
    st.write(
        "Provide the event ID and the SHA-256 hash of the original payload. "
        "The gateway compares it against the on-chain stored hash and validates the signature."
    )

    ev_id = st.text_input("Event ID", placeholder="evt-abc123...")
    payload_hash_input = st.text_input(
        "Payload Hash (SHA-256 hex)",
        placeholder="e3b0c44298fc1c149afbf4c8996fb924..."
    )

    if st.button("Verify"):
        if not ev_id or not payload_hash_input:
            st.warning("Provide both an event ID and a payload hash.")
        else:
            with st.spinner("Verifying..."):
                result = api(
                    f"/verify?event_id={ev_id}",
                    method="POST",
                    json={"payload_hash": payload_hash_input},
                )
            if result:
                if result.get("match"):
                    st.success(f"PASS — Hash matches on-chain record.")
                else:
                    st.error(f"FAIL — Hash mismatch. Tampering detected.")

                sig_valid = result.get("signature_valid")
                if sig_valid is True:
                    st.success("Signature valid — record was produced by the authorised gateway.")
                elif sig_valid is False:
                    st.error("Signature invalid — record may not originate from the authorised gateway.")

                st.json({
                    "event_id": result.get("event_id"),
                    "result": result.get("result"),
                    "stored_hash": result.get("stored_hash"),
                    "submitted_hash": result.get("submitted_hash"),
                    "signature_valid": sig_valid,
                })

    st.divider()
    st.subheader("Inspect Event Record")
    lookup_id = st.text_input("Event ID to inspect", key="lookup")
    if st.button("Fetch Record"):
        record = api(f"/events/{lookup_id}")
        if record:
            st.json(record)
            history = api(f"/events/{lookup_id}/history")
            if history:
                write_count = len(history) if isinstance(history, list) else 0
                if write_count == 1:
                    st.success(f"Write history: 1 write — no modification attempts recorded.")
                elif write_count > 1:
                    st.error(f"Write history: {write_count} writes — investigation required.")
                st.json(history)


# --- Tab 3: Metrics ---
with tab_metrics:
    st.subheader("Runtime Metrics")

    metrics = api("/metrics")
    if metrics:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Submitted", metrics.get("total_submitted", 0))
        col2.metric("Successful", metrics.get("total_success", 0))
        col3.metric("Failed", metrics.get("total_failed", 0))
        col4.metric("Throughput (tx/s)", f"{metrics.get('throughput_tps', 0):.3f}")

        col5, col6, col7 = st.columns(3)
        col5.metric("Avg Latency (ms)", f"{metrics.get('avg_latency_ms', 0):.1f}")
        col6.metric("P95 Latency (ms)", f"{metrics.get('p95_latency_ms', 0):.1f}")
        col7.metric("P99 Latency (ms)", f"{metrics.get('p99_latency_ms', 0):.1f}")

        st.caption(f"Run ID: {metrics.get('run_id')} — Started: {metrics.get('started_at')}")

    if st.button("Export Metrics to CSV"):
        result = api("/metrics/export", method="POST")
        if result:
            st.success(f"Exported to: {result.get('exported_to')}")


# --- Tab 4: Simulate Tampering ---
with tab_tamper:
    st.subheader("Tamper Detection Demo")
    st.write(
        "This demo submits a real event, then modifies one field, and shows "
        "that the ledger detects the modification. "
        "This is the core non-repudiation demonstration."
    )

    if "tamper_event" not in st.session_state:
        st.session_state["tamper_event"] = None
        st.session_state["tamper_canonical"] = None
        st.session_state["tamper_hash"] = None

    col_a, col_b = st.columns(2)
    actor = col_a.text_input("Actor ID", value="W001")
    zone = col_b.text_input("Zone ID", value="Z04")

    if st.button("Submit Test Event"):
        payload = {
            "event_type": "NEAR_MISS",
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "site_id": "site-torino-01",
            "zone_id": zone,
            "actor_id": actor,
            "severity": 4,
            "source": "simulator",
            "payload_extra": {"clearance_m": 0.4, "equipment_id": "EQ-CRANE-01"},
        }
        with st.spinner("Submitting event..."):
            resp = api("/events", method="POST", json=payload)
        if resp:
            st.session_state["tamper_event"] = resp
            # Build canonical payload matching gateway logic
            canonical_keys = ["schema_version", "event_type", "ts", "site_id",
                              "zone_id", "actor_id", "severity", "source", "payload_extra"]
            canonical = {k: payload.get(k) for k in canonical_keys if payload.get(k) is not None}
            canonical["schema_version"] = "1.0"
            canonical_str = json.dumps(
                dict(sorted(canonical.items())), separators=(",", ":"), ensure_ascii=False
            )
            st.session_state["tamper_canonical"] = canonical_str
            st.session_state["tamper_hash"] = resp.get("payload_hash")
            st.success(f"Event submitted: {resp['event_id']}")
            st.json(resp)

    if st.session_state["tamper_event"]:
        ev = st.session_state["tamper_event"]
        ev_id = ev["event_id"]
        original_hash = ev["payload_hash"]

        st.divider()
        st.markdown("**Step 1 — Verify original payload (expected: PASS)**")
        if st.button("Verify Original"):
            result = api(f"/verify?event_id={ev_id}", method="POST",
                         json={"payload_hash": original_hash})
            if result:
                if result["match"]:
                    st.success("PASS — Hash matches on-chain record.")
                else:
                    st.error("FAIL — Unexpected mismatch.")
                st.json(result)

        st.divider()
        st.markdown("**Step 2 — Tamper with the payload (change severity 4 -> 1)**")

        tampered_canonical = st.session_state["tamper_canonical"]
        if tampered_canonical:
            try:
                obj = json.loads(tampered_canonical)
                obj["severity"] = 1
                tampered_str = json.dumps(
                    dict(sorted(obj.items())), separators=(",", ":"), ensure_ascii=False
                )
                tampered_hash = hashlib.sha256(tampered_str.encode()).hexdigest()
            except Exception:
                tampered_hash = "error"

            st.code(
                f"Original severity : 4\n"
                f"Tampered severity : 1\n\n"
                f"Original hash  : {original_hash[:32]}...\n"
                f"Tampered hash  : {tampered_hash[:32]}...",
                language="text",
            )

            if st.button("Verify Tampered Payload (expected: FAIL)"):
                result = api(f"/verify?event_id={ev_id}", method="POST",
                             json={"payload_hash": tampered_hash})
                if result:
                    if not result["match"]:
                        st.error("FAIL — Tamper detected. Hashes do not match.")
                    else:
                        st.warning("PASS — unexpected (check implementation).")
                    st.json(result)
