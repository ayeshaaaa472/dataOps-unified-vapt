import os
import datetime
from urllib.parse import urlparse
import pandas as pd
import streamlit as st

# Custom imports
from parser import parse_zap_json
from nmap_scanner import execute_and_export, validate_target
from ai_correlator import run_ai_correlation

st.set_page_config(page_title="VAPT Triage Copilot", layout="wide")

# Persistent audit log
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "current_findings" not in st.session_state:
    st.session_state["current_findings"] = []

if "triage_report" not in st.session_state:
    st.session_state["triage_report"] = None


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


# Sidebar Configuration
st.sidebar.title("⚙️ Engine Configuration")
gemini_key = st.sidebar.text_input(
    "Gemini API Key (Optional Override)",
    type="password",
    value="",
    help="Defaults to GEMINI_API_KEY from .env if left blank."
)

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

# --- Render Results ---
if st.session_state.get("current_findings"):
    st.subheader("📊 Ingested Tool Findings")
    for item in st.session_state["current_findings"]:
        with st.expander(f"[{item.get('severity', 'info').upper()}] {item.get('title', 'Finding')} ({item.get('tool', 'tool')})"):
            st.write(f"**Target:** `{item.get('target', 'N/A')}:{item.get('port', 'N/A')}`")
            st.write(f"**Evidence:** `{item.get('evidence', 'N/A')}`")
            st.write(f"**Description:** {item.get('description', 'N/A')}")

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
    if actions:
        st.dataframe(pd.DataFrame(actions), use_container_width=True)
    else:
        st.info("No specific actions generated.")

# Sidebar: Live Audit Log
st.sidebar.markdown("---")
st.sidebar.title("📋 Activity Audit Log")
if st.session_state.audit_log:
    for entry in reversed(st.session_state.audit_log):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n{'-'*25}")
else:
    st.sidebar.caption("No activities recorded yet.")