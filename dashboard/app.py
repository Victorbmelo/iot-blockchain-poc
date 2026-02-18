"""
Audit Layer Dashboard - Streamlit

Four tabs:
  1. Live Events - timeline with severity heatmap, filter by actor/zone/type
  2. Integrity - verify payload hash + signature, inspect write history
  3. Demo Scenes - scripted walkthrough of the 3 presentation scenarios
  4. Metrics - latency P95/P99, throughput, error rate

Run:
    streamlit run dashboard/app.py
"""
import hashlib
import json
import time
import unicodedata
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(
    page_title="Audit Layer - Construction Site Safety",
    page_icon="A",
    layout="wide",
    initial_sidebar_state="expanded",
)

#  Sidebar 
with st.sidebar:
    st.title("A Audit Layer")
    st.caption("Politecnico di Torino - Laurea Magistrale")
    GATEWAY = st.text_input("Gateway URL", value="http://localhost:8080")
    ROLE = st.selectbox("Your role", ["inspector", "contractor", "safety_manager", "insurer"],
                        index=0)
    st.divider()
    if st.button("🔄 Refresh"):
        st.rerun()


def api(path, method="GET", role=None, **kwargs):
    headers = {"X-Role": role or ROLE}
    try:
        resp = requests.request(method, f"{GATEWAY}{path}",
                                headers=headers, timeout=8, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        st.error(f"HTTP {exc.response.status_code}: {exc.response.text[:120]}")
        return None
    except Exception as exc:
        st.error(f"Gateway error: {exc}")
        return None


def canonical_hash(payload: dict) -> str:
    def sort_keys(obj):
        if isinstance(obj, dict):
            return {k: sort_keys(obj[k]) for k in sorted(obj.keys())}
        if isinstance(obj, list):
            return [sort_keys(v) for v in obj]
        return obj
    raw = json.dumps(sort_keys(payload), separators=(",", ":"), ensure_ascii=False)
    raw = unicodedata.normalize("NFC", raw)
    return hashlib.sha256(raw.encode()).hexdigest()


#  Health banner 
health = api("/health")
if health:
    mode = "Fabric" if not health.get("stub_mode") else "Stub"
    st.success(f"Gateway connected - Mode: **{mode}** - Schema: **{health.get('schema_version')}** "
               f"- Signer: **{health.get('signer_id')}**")
else:
    st.error("Gateway unreachable. Start with: `make up-stub`")
    st.stop()

tab_events, tab_integrity, tab_demo, tab_metrics = st.tabs([
    "1 Live Events", "2 Integrity & Verification", "3 Demo Scenes", "4 Metrics"
])


#  Tab 1: Live Events 
with tab_events:
    st.subheader("Event Timeline")

    col1, col2, col3 = st.columns(3)
    filter_by = col1.selectbox("Filter by", ["all", "zone", "actor", "event_type"], key="evt_filter")
    filter_val = col2.text_input("Value", placeholder="Z04 / W001 / NEAR_MISS", key="evt_val")
    page_size = col3.slider("Page size", 10, 200, 50, key="evt_page")

    if st.button("Load Events", key="load_events"):
        with st.spinner("Fetching..."):
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
                        df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

                st.metric("Events loaded", len(df))

                SEVERITY_COLORS = {0: "#6b7280", 1: "#3b82f6", 2: "#10b981",
                                   3: "#f59e0b", 4: "#f97316", 5: "#ef4444"}

                if "ts" in df.columns and "eventType" in df.columns:
                    fig = px.scatter(
                        df.dropna(subset=["ts"]),
                        x="ts", y="eventType",
                        color="severity",
                        color_continuous_scale=[[0, "#6b7280"], [0.4, "#10b981"],
                                                [0.6, "#f59e0b"], [0.8, "#f97316"],
                                                [1.0, "#ef4444"]],
                        range_color=[0, 5],
                        hover_data=["actorId", "zoneId", "source", "eventId"],
                        title="Safety Event Timeline",
                        height=380,
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        margin=dict(l=0, r=0, t=40, b=0),
                    )
                    st.plotly_chart(fig, use_container_width=True)

                c1, c2 = st.columns(2)
                if "eventType" in df.columns:
                    type_counts = df["eventType"].value_counts().reset_index()
                    type_counts.columns = ["eventType", "count"]
                    fig2 = px.bar(type_counts, x="eventType", y="count",
                                  title="By Event Type", color="count",
                                  color_continuous_scale="Oranges")
                    fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                                       plot_bgcolor="rgba(0,0,0,0)", showlegend=False,
                                       margin=dict(l=0, r=0, t=40, b=0))
                    c1.plotly_chart(fig2, use_container_width=True)

                if "severity" in df.columns:
                    sev_counts = df["severity"].value_counts().sort_index().reset_index()
                    sev_counts.columns = ["severity", "count"]
                    labels = {0: "0-Info", 1: "1-Low", 2: "2-Med",
                              3: "3-Elev", 4: "4-High", 5: "5-Crit"}
                    sev_counts["label"] = sev_counts["severity"].map(labels)
                    colors = [SEVERITY_COLORS.get(s, "#6b7280") for s in sev_counts["severity"]]
                    fig3 = px.bar(sev_counts, x="label", y="count",
                                  title="By Severity", color="label",
                                  color_discrete_sequence=colors)
                    fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                                       plot_bgcolor="rgba(0,0,0,0)", showlegend=False,
                                       margin=dict(l=0, r=0, t=40, b=0))
                    c2.plotly_chart(fig3, use_container_width=True)

                st.dataframe(df, use_container_width=True, height=300)
            else:
                st.info("No events found. Run `make seed` to populate the ledger.")

    with st.expander("Stats overview"):
        stats = api("/stats", role="safety_manager")
        if stats:
            c1, c2, c3 = st.columns(3)
            c1.metric("Total events", stats.get("total_events", 0))
            by_type = stats.get("by_event_type", {})
            c2.metric("Near-misses", by_type.get("NEAR_MISS", 0))
            c3.metric("Falls", by_type.get("FALL_DETECTED", 0))


#  Tab 2: Integrity & Verification 
with tab_integrity:
    st.subheader("Integrity Verification")
    st.write(
        "Provide the event ID and the SHA-256 hash of the canonical payload. "
        "The gateway compares it against the on-chain stored hash and validates the ECDSA signature."
    )

    col1, col2 = st.columns([1, 2])
    ev_id = col1.text_input("Event ID", placeholder="evt-abc123...", key="v_eid")
    ph_input = col2.text_input("Payload Hash (SHA-256 hex)",
                                placeholder="e3b0c44298fc1c149afbf4c8996...", key="v_hash")

    if st.button("Verify", key="do_verify"):
        if not ev_id or not ph_input:
            st.warning("Provide both an event ID and a payload hash.")
        else:
            with st.spinner("Verifying..."):
                result = api(f"/verify?event_id={ev_id}", method="POST",
                             json={"payload_hash": ph_input}, role="inspector")
            if result:
                if result.get("match"):
                    st.success("**PASS** - Hash matches on-chain record.")
                else:
                    st.error("**FAIL** - Hash mismatch. Tampering detected.")

                sig = result.get("signature_valid")
                if sig is True:
                    st.success("Signature valid - produced by the authorised gateway.")
                elif sig is False:
                    st.error("Signature invalid - record may not originate from authorised gateway.")
                st.json(result)

    st.divider()
    st.subheader("Write History (Tamper Evidence)")
    st.write(
        "A legitimate record has **exactly one** write entry. "
        "Two or more entries would indicate a modification attempt."
    )
    hist_id = st.text_input("Event ID to inspect", key="hist_id")
    if st.button("Get History", key="get_hist"):
        if hist_id:
            record = api(f"/events/{hist_id}", role="inspector")
            if record:
                c1, c2 = st.columns(2)
                c1.metric("payloadHash", record.get("payloadHash", "")[:16] + "...")
                c1.metric("recordedByMSP", record.get("recordedByMSP", ""))
                c2.metric("tsLedger", record.get("tsLedger", ""))
                c2.metric("signerId", record.get("signerId", ""))

            history = api(f"/events/{hist_id}/history", role="inspector")
            if isinstance(history, list):
                write_count = len(history)
                if write_count == 1:
                    st.success(f"Write history: **1 entry** - no modification attempts.")
                elif write_count > 1:
                    st.error(f"Write history: **{write_count} entries** - investigation required.")
                else:
                    st.info("No history found.")
                if history:
                    st.json(history)


#  Tab 3: Demo Scenes 
with tab_demo:
    st.subheader("Demo Scenes")
    st.write(
        "These scenes replicate the scripted presentation demo. "
        "Each button submits real events to the gateway and shows results inline."
    )

    #  Scene 1 
    with st.expander("Scene 1 - Normal Monitoring: Worker enters hazardous zone", expanded=True):
        st.write("Worker W001 enters zone Z04 (Crane Operation Zone). The system records a "
                 "HAZARD_ENTRY event and a PROXIMITY_ALERT, chained via prevEventHash.")

        if st.button("Run Scene 1", key="s1"):
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            import secrets as _sec

            with st.spinner("Recording HAZARD_ENTRY..."):
                entry = api("/events", method="POST", role="contractor", json={
                    "event_type": "HAZARD_ENTRY", "ts": ts,
                    "site_id": "site-torino-01", "zone_id": "Z04",
                    "actor_id": "W001", "severity": 3, "source": "proximity_tag",
                    "nonce": _sec.token_hex(6),
                    "payload_extra": {"restricted": True, "gps_lat": 45.0712, "gps_lon": 7.6871},
                })

            if entry:
                st.success(f"HAZARD_ENTRY recorded - ID: `{entry['event_id']}`")
                prev_hash = entry["payload_hash"]

                with st.spinner("Recording PROXIMITY_ALERT..."):
                    prox = api("/events", method="POST", role="contractor", json={
                        "event_type": "PROXIMITY_ALERT", "ts": ts,
                        "site_id": "site-torino-01", "zone_id": "Z04",
                        "actor_id": "W001", "severity": 4, "source": "proximity_tag",
                        "prev_event_hash": prev_hash, "nonce": _sec.token_hex(6),
                        "payload_extra": {"distance_m": 0.8, "equipment_id": "EQ-CRANE-01"},
                    })

                if prox:
                    st.success(f"PROXIMITY_ALERT recorded - ID: `{prox['event_id']}`")
                    st.info(f"Chain: HAZARD_ENTRY → PROXIMITY_ALERT (prevEventHash: `{prev_hash[:16]}...`)")

                    # Inspector verifies the entry
                    verify = api(f"/verify?event_id={entry['event_id']}", method="POST",
                                 role="inspector", json={"payload_hash": entry["payload_hash"]})
                    if verify and verify.get("match"):
                        st.success("Inspector verification: **PASS** - record intact on ledger.")
                    st.json({"entry": entry, "proximity": prox})

    #  Scene 2 
    with st.expander("Scene 2 - Near-Miss Escalation Chain"):
        st.write("Worker W007: ZONE_ENTRY → PPE_VIOLATION → PROXIMITY_ALERT → NEAR_MISS. "
                 "Each event chains to the previous via prevEventHash.")

        if st.button("Run Scene 2", key="s2"):
            import secrets as _sec2
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            prev = ""
            chain = []

            steps = [
                ("ZONE_ENTRY", "Z08", 1, {"gate": "main"}),
                ("ZONE_ENTRY", "Z02", 2, {"ppe_ok": True}),
                ("PPE_VIOLATION", "Z02", 3, {"missing": ["helmet"]}),
                ("PROXIMITY_ALERT", "Z02", 4, {"distance_m": 1.2, "equipment_id": "EQ-CRANE-01"}),
                ("NEAR_MISS", "Z02", 4, {"clearance_m": 0.2, "equipment_id": "EQ-CRANE-01"}),
            ]

            progress = st.progress(0)
            for i, (etype, zone, sev, extra) in enumerate(steps):
                resp = api("/events", method="POST", role="contractor", json={
                    "event_type": etype, "ts": ts, "site_id": "site-torino-01",
                    "zone_id": zone, "actor_id": "W007", "severity": sev,
                    "source": "wearable", "prev_event_hash": prev,
                    "nonce": _sec2.token_hex(6), "payload_extra": extra,
                })
                if resp:
                    chain.append({"step": etype, "event_id": resp["event_id"],
                                  "prev_hash": prev[:12] if prev else ""})
                    prev = resp["payload_hash"]
                progress.progress((i + 1) / len(steps))
                time.sleep(0.3)

            if chain:
                st.success(f"Chain of {len(chain)} events recorded.")
                df_chain = pd.DataFrame(chain)
                df_chain.index = range(1, len(df_chain) + 1)
                st.dataframe(df_chain, use_container_width=True)
                st.info("The prevEventHash links form a tamper-evident chain. "
                        "Removing any event would break the chain, detectable via TraceChain.")

    #  Scene 3 
    with st.expander("Scene 3 - Tamper Detection (Core Demo)"):
        st.write(
            "A NEAR_MISS event is submitted. An attacker modifies the severity field (4 → 1). "
            "The ledger detects the modification."
        )

        if "tamper_state" not in st.session_state:
            st.session_state.tamper_state = {}

        ts_demo = datetime.now(timezone.utc).isoformat(timespec="seconds")

        col_a, col_b = st.columns(2)
        actor = col_a.text_input("Actor ID", value="W001", key="t_actor")
        zone = col_b.text_input("Zone ID", value="Z04", key="t_zone")

        if st.button("Submit Event (contractor)", key="t_submit"):
            import secrets as _sec3
            ev = {
                "event_type": "NEAR_MISS", "ts": ts_demo,
                "site_id": "site-torino-01", "zone_id": zone,
                "actor_id": actor, "severity": 4, "source": "camera",
                "nonce": _sec3.token_hex(8),
                "payload_extra": {"clearance_m": 0.4, "equipment_id": "EQ-CRANE-01"},
            }
            resp = api("/events", method="POST", role="contractor", json=ev)
            if resp:
                st.session_state.tamper_state = {
                    "event_id": resp["event_id"],
                    "payload_hash": resp["payload_hash"],
                    "signature": resp["signature"],
                    "original_ev": ev,
                }
                st.success(f"Event submitted: `{resp['event_id']}`")
                st.info(f"Payload hash: `{resp['payload_hash']}`  \n"
                        f"Signature: `{resp['signature'][:40]}...`")

        ts = st.session_state.tamper_state

        if ts.get("event_id"):
            st.divider()
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Step 1 - Verify original (expected: PASS)**")
                if st.button("Verify Original", key="t_orig"):
                    result = api(f"/verify?event_id={ts['event_id']}", method="POST",
                                 role="inspector", json={"payload_hash": ts["payload_hash"]})
                    if result:
                        if result["match"]:
                            st.success("**PASS** ✓")
                        else:
                            st.error("FAIL (unexpected)")
                        st.json({
                            "result": result["result"],
                            "signature_valid": result.get("signature_valid"),
                        })

            with col2:
                st.markdown("**Step 2 - Simulate tampering: severity 4 → 1**")
                st.code(
                    'original:  { "severity": 4, ... }\n'
                    'tampered:  { "severity": 1, ... }\n\n'
                    '→ different SHA-256 → FAIL on verify',
                    language="text",
                )

                ev_orig = ts["original_ev"]
                tampered = {
                    "schema_version": "1.0",
                    "event_type": ev_orig["event_type"],
                    "ts": ev_orig["ts"],
                    "site_id": ev_orig["site_id"],
                    "zone_id": ev_orig["zone_id"],
                    "actor_id": ev_orig["actor_id"],
                    "severity": 1,  # tampered
                    "source": ev_orig["source"],
                    "payload_extra": ev_orig.get("payload_extra"),
                }
                tampered_hash = canonical_hash(tampered)
                st.caption(f"Tampered hash: `{tampered_hash[:32]}...`")

                if st.button("Verify Tampered (expected: FAIL)", key="t_tamper"):
                    result2 = api(f"/verify?event_id={ts['event_id']}", method="POST",
                                  role="inspector", json={"payload_hash": tampered_hash})
                    if result2:
                        if not result2["match"]:
                            st.error("**FAIL** ✗ - Tamper detected.")
                            st.success("The ledger record is intact. Modification is forensically evident.")
                        else:
                            st.warning("Match (unexpected - check implementation)")
                        st.json({
                            "stored_hash": result2["stored_hash"][:32] + "...",
                            "submitted_hash": result2["submitted_hash"][:32] + "...",
                            "match": result2["match"],
                        })


#  Tab 4: Metrics 
with tab_metrics:
    st.subheader("Runtime Metrics")

    m = api("/metrics")
    if m:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Submitted", m.get("total_submitted", 0))
        col2.metric("Successful", m.get("total_success", 0))
        col3.metric("Failed", m.get("total_failed", 0))
        col4.metric("Throughput (tx/s)", f"{m.get('throughput_tps', 0):.4f}")

        col5, col6, col7 = st.columns(3)
        col5.metric("Avg Latency (ms)", f"{m.get('avg_latency_ms', 0):.1f}")
        col6.metric("P95 Latency (ms)", f"{m.get('p95_latency_ms', 0):.1f}")
        col7.metric("P99 Latency (ms)", f"{m.get('p99_latency_ms', 0):.1f}")

        st.caption(f"Run ID: `{m.get('run_id')}`  Started: {m.get('started_at')}")

        if st.button("Export Metrics CSV"):
            result = api("/metrics/export", method="POST")
            if result:
                st.success(f"Exported to: `{result.get('exported_to')}`")
                st.caption("Files: events.csv, metrics.csv - use these for Chapter 5 tables.")

    st.divider()
    with st.expander("Access Control Matrix"):
        roles_data = api("/roles")
        if roles_data:
            perms = roles_data.get("permissions", {})
            all_ops = sorted({op for ops in perms.values() for op in ops})
            rows = []
            for role, role_ops in perms.items():
                row = {"Role": role}
                for op in all_ops:
                    row[op] = "✓" if op in role_ops else ""
                rows.append(row)
            if rows:
                df_roles = pd.DataFrame(rows).set_index("Role")
                st.dataframe(df_roles, use_container_width=True)
            st.caption(roles_data.get("note", ""))
