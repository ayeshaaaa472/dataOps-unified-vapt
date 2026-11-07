import os
import datetime
from urllib.parse import urlparse
import pandas as pd
import streamlit as st

# Custom imports
from parser import parse_zap_json
from nmap_scanner import execute_and_export, validate_target
from ai_correlator import run_ai_correlation
from prober import execute_benign_probe
from dotenv import load_dotenv
from report_generator import generate_pdf_report

load_dotenv()

st.set_page_config(page_title="VAPT Triage Copilot", layout="wide")

# Persistent state
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "current_findings" not in st.session_state:
    st.session_state["current_findings"] = []

if "triage_report" not in st.session_state:
    st.session_state["triage_report"] = None

# Task 6: Store HITL Decisions and Probe Results
if "hitl_decisions" not in st.session_state:
    st.session_state["hitl_decisions"] = {}


def add_audit_entry(action: str, status: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.audit_log.append({
        "timestamp": timestamp,
        "action": action,
        "status": status
    })


def is_scope_allowed(target_str: str) -> bool:
    clean_target = target_str.strip().lower()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    hostname = parsed.hostname or ""
    return validate_target(hostname)


<<<<<<< HEAD
# API Key loaded directly from environment
gemini_key = os.getenv("GEMINI_API_KEY", "")
=======
# Silently load the key in the background
gemini_key = os.getenv("GEMINI_API_KEY")
>>>>>>> 490df7b (Task 7 complete: Integrated automated VAPT PDF audit report export)

st.title("🛡️ AI VAPT Triage & Prioritization Copilot")
st.caption("Human-in-the-Loop Security Assessment & Contextual Risk Prioritization")

target_input = st.text_input("Target Scope (Local sandbox):", "127.0.0.1:3000")

uploaded_zap_file = st.file_uploader(
    "Upload OWASP ZAP Report (JSON)",
    type=["json"],
    help="Upload an exported ZAP report to correlate against network findings.",
)

if st.button("🚀 Start Assessment"):
    clean_target = target_input.strip()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    target_ip = parsed.hostname or "127.0.0.1"
    target_port = str(parsed.port or "3000")

    if not is_scope_allowed(target_input):
        st.error(f"❌ Scope Violation: '{target_input}' is an invalid address.")
        add_audit_entry(f"Scope violation for {target_input}", "BLOCKED")
    else:
        add_audit_entry(f"Assessment started against {target_ip}:{target_port}", "AUTHORIZED")
        st.success(f"Target '{target_ip}:{target_port}' locked and authorized.")

        # 1. Run Live Scanner
        with st.spinner("Running network reconnaissance..."):
            try:
                network_findings = execute_and_export(target=target_ip, ports=target_port)
            except Exception as e:
                st.error(f"Scanner error: {e}")
                network_findings = []

        # 2. Ingest Application Scans (ZAP)
        web_findings = []
        if uploaded_zap_file is not None:
            temp_path = os.path.join("imports", "uploaded_zap.json")
            os.makedirs("imports", exist_ok=True)
            with open(temp_path, "wb") as f:
                f.write(uploaded_zap_file.getbuffer())
            web_findings = parse_zap_json(temp_path)
            add_audit_entry(f"Loaded uploaded report: {uploaded_zap_file.name}", "OK")
        else:
            zap_file = os.path.join("imports", "sample_zap_report.json")
            if os.path.exists(zap_file):
                web_findings = parse_zap_json(zap_file)
                add_audit_entry("Loaded default sample ZAP report", "FALLBACK")

        # Merge findings
        all_findings = network_findings + web_findings
        st.session_state["current_findings"] = all_findings

        # 3. Trigger AI Correlation Engine
        effective_key = gemini_key.strip() or os.getenv("GEMINI_API_KEY")
        with st.spinner("Analyzing threat posture and correlating findings with AI..."):
            try:
                analysis = run_ai_correlation(
                    findings=all_findings,
                    api_key=effective_key
                )
                st.session_state["triage_report"] = analysis
                provider = analysis.get("provider_used", "AI")
                add_audit_entry(f"AI correlation completed via {provider}", "SUCCESS")
            except Exception as err:
                st.session_state["triage_report"] = None
                st.error(f"AI correlation failed: {err}")
                add_audit_entry("AI Correlation", f"FAILED: {err}")

# --- Task 5 & Task 6: Evidence Viewer & HITL Verification Cards ---
if st.session_state.get("current_findings"):
    st.subheader(f"📊 Verified Findings & Evidence Cards ({len(st.session_state['current_findings'])})")

    ai_tag_lookup = {}
    if st.session_state.get("triage_report"):
        for entry in st.session_state["triage_report"].get("analyzed_findings", []):
            ai_tag_lookup[entry.get("finding_id")] = entry

    for idx, item in enumerate(st.session_state["current_findings"]):
        fid = item.get("id", f"F-{idx+1}")
        title = item.get("title", "Finding")
        tool = item.get("tool", "Scanner")
        severity = item.get("severity", "INFO").upper()
        raw_evidence = item.get("evidence", "No explicit payload or banner captured.")
        description = item.get("description", "No description available.")

        # Dynamically inherit target scope entered by the user
        clean_scoped = target_input.replace("http://", "").replace("https://", "").strip().split("/")[0]
        scoped_host = clean_scoped.split(":")[0] if ":" in clean_scoped else clean_scoped
        scoped_port = clean_scoped.split(":")[1] if ":" in clean_scoped else "80"

        raw_target = str(item.get("target", "")).strip()
        raw_port = str(item.get("port", "")).strip()

        target_host = raw_target if raw_target and "unknown" not in raw_target.lower() and " " not in raw_target else scoped_host
        target_port = raw_port if raw_port and "unknown" not in raw_port.lower() and raw_port != "None" else scoped_port
        target_endpoint = f"{target_host}:{target_port}"

        ai_data = ai_tag_lookup.get(fid, {})
        confidence = ai_data.get("confidence")
        if not confidence:
            confidence = "HIGH" if raw_evidence and raw_evidence != "N/A" else "MEDIUM"

        conf_colors = {"HIGH": "green", "MEDIUM": "orange", "LOW": "gray"}
        conf_badge = f":{conf_colors.get(confidence.upper(), 'gray')}[{confidence.upper()} CONFIDENCE]"

        ai_reason = ai_data.get(
            "ai_reason",
            f"Vulnerability observed via {tool}. Verify network exposure on port {target_port}."
        )

        with st.expander(f"[{severity}] {title} ({tool}) — {conf_badge}", expanded=True):
            col_meta1, col_meta2 = st.columns(2)
            with col_meta1:
                st.markdown(f"**Target:** `{target_endpoint}`")
                st.markdown(f"**Origin Tool:** `{tool}` (ID: `{fid}`)")
            with col_meta2:
                st.markdown(f"**Confidence Rating:** {conf_badge}")

            st.markdown(f"**Description:** {description}")
            st.info(f"💡 **AI Reason Tag:** {ai_reason}")
            st.markdown("**🔬 Raw Tool Snippet & Payload:**")
            st.code(raw_evidence, language="bash" if "nmap" in tool.lower() else "http")

            # --- Task 6: HITL Approval & Benign Probe Gate ---
            st.markdown("---")
            st.markdown("##### 🛡️ Human-in-the-Loop Validation Gate")
            
            current_status = st.session_state["hitl_decisions"].get(fid, {}).get("status", "PENDING")

            btn_col1, btn_col2, status_col = st.columns([1, 1, 2])

            with btn_col1:
                if st.button("✅ Approve & Probe", key=f"app_{fid}"):
                    probe_res = execute_benign_probe(target=target_host, port=target_port)
                    st.session_state["hitl_decisions"][fid] = {
                        "status": "APPROVED",
                        "probe": probe_res
                    }
                    add_audit_entry(f"HITL Approved: {fid} -> Benign Probe Executed", "APPROVED")
                    st.rerun()

            with btn_col2:
                if st.button("❌ Reject", key=f"rej_{fid}"):
                    st.session_state["hitl_decisions"][fid] = {
                        "status": "REJECTED",
                        "probe": None
                    }
                    add_audit_entry(f"HITL Rejected by analyst: {fid}", "REJECTED")
                    st.rerun()

            with status_col:
                if current_status == "APPROVED":
                    probe_data = st.session_state["hitl_decisions"][fid].get("probe") or {}
                    st.success(f"**Status:** APPROVED | {probe_data.get('message', 'Probe Complete')}")
                elif current_status == "REJECTED":
                    st.error("**Status:** REJECTED (Dismissed from active verification)")
                else:
                    st.warning("**Status:** PENDING ANALYST REVIEW")

# --- Render AI Triage Analysis ---
if st.session_state.get("triage_report"):
    report = st.session_state["triage_report"]
    st.markdown("---")
    st.header("🧠 AI Contextual Prioritization & Attack Analysis")

    score = report.get("overall_risk_score", "UNKNOWN")
    badge_colors = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "blue",
        "LOW": "green"
    }
    badge_color = badge_colors.get(score.upper(), "grey")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader(f"Overall Risk Posture: :{badge_color}[{score.upper()}]")
    with col2:
        st.caption(f"Provider: **{report.get('provider_used', 'AI')}**")

    st.markdown("#### 📋 Executive Summary")
    st.info(report.get("executive_summary", "No summary generated."))

    st.markdown("#### ⛓️ Attack Path & Vector Synthesis")
    st.warning(report.get("attack_path_analysis", "No attack chain identified."))

    st.markdown("#### 🎯 Prioritized Defensive Actions")
    actions = report.get("prioritized_actions", [])

    # Filter out actions for findings rejected by the analyst (exact ID and keyword match)
    rejected_ids = {
        fid for fid, data in st.session_state.get("hitl_decisions", {}).items()
        if data.get("status") == "REJECTED"
    }

    # Find keywords or titles associated with rejected findings
    rejected_keywords = set()
    for item in st.session_state.get("current_findings", []):
        item_id = item.get("id")
        if item_id in rejected_ids:
            for word in item.get("title", "").lower().split():
                if len(word) > 3:
                    rejected_keywords.add(word)

    active_actions = []
    for act in actions:
        act_id = str(act.get("finding_id", "")).strip()
        act_desc = str(act.get("action", "")).lower()

        # Check direct ID match or substring keyword match
        direct_match = act_id in rejected_ids or any(rej_id.lower() in act_id.lower() for rej_id in rejected_ids)
        content_match = any(kw in act_desc or kw in act_id.lower() for kw in rejected_keywords)

        if not (direct_match or content_match):
            active_actions.append(act)

    if active_actions:
        st.dataframe(pd.DataFrame(active_actions), use_container_width=True)
    elif actions and not active_actions:
        st.success("All actions dismissed — corresponding findings were rejected as false positives.")
    else:
        st.info("No specific actions generated.")

# Sidebar: Live Audit Log
st.sidebar.title("📋 Activity Audit Log")
if st.session_state.audit_log:
    for entry in reversed(st.session_state.audit_log):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n{'-'*25}")
else:
    st.sidebar.caption("No activities recorded yet.")

    # --- Task 7: Report Download Section ---
if st.session_state.get("triage_report"):
    st.markdown("---")
    st.subheader("📄 Export Assessment Report")

    try:
        pdf_bytes = generate_pdf_report(
            target=target_input,
            analysis_data=st.session_state["triage_report"],
            findings=st.session_state.get("current_findings", []),
            audit_log=st.session_state.get("audit_log", [])
        )

        st.download_button(
            label="📥 Download Full VAPT Audit Report (PDF)",
            data=pdf_bytes,
            file_name=f"VAPT_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf"
        )
    except Exception as e:
        st.error(f"Error generating PDF report: {e}")