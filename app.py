import os
import streamlit as st
import pandas as pd
from urllib.parse import urlparse
import datetime

# Import scanners and correlator
from parser import parse_zap_json
from nmap_scanner import execute_and_export, validate_target, validate_ports
from ai_correlator import run_ai_correlation

st.set_page_config(page_title="VAPT Triage Copilot", layout="wide")

# Persistent audit log
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

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
    "Gemini API Key",
    type="password",
    value=os.getenv("GEMINI_API_KEY", ""),
    help="Enter your Google Gemini API key to enable AI-driven correlation."
)

st.title("🛡️ AI VAPT Triage & Prioritization Copilot")
st.caption("Human-in-the-Loop Security Assessment & Contextual Risk Prioritization")

target_input = st.text_input("Target Scope (Local sandbox):", "127.0.0.1:3000")

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
        zap_file = os.path.join("imports", "sample_zap_report.json")
        web_findings = parse_zap_json(zap_file) if os.path.exists(zap_file) else []

        # Merge findings
        all_findings = network_findings + web_findings
        st.session_state["current_findings"] = all_findings

        st.subheader("📊 Ingested Tool Findings")
        if all_findings:
            for item in all_findings:
                with st.expander(f"[{item.get('severity', 'info').upper()}] {item.get('title', 'Finding')} ({item.get('tool', 'tool')})"):
                    st.write(f"**Target:** `{item.get('target', target_ip)}:{item.get('port', target_port)}`")
                    st.write(f"**Evidence:** `{item.get('evidence', 'N/A')}`")
                    st.write(f"**Description:** {item.get('description', 'N/A')}")
        else:
            st.info("No open ports or findings detected for this target.")

# --- Task 3: AI Correlation Section ---
if "current_findings" in st.session_state and st.session_state["current_findings"]:
    st.markdown("---")
    st.subheader("🧠 AI-Driven Risk Prioritization & Correlation")

    if st.button("⚡ Run AI Correlation & Attack Path Analysis"):
        if not gemini_key:
            st.warning("Please provide a Gemini API Key in the left sidebar to proceed.")
        else:
            with st.spinner("Analyzing cross-layer findings with Gemini..."):
                try:
                    analysis = run_ai_correlation(
                        findings=st.session_state["current_findings"],
                        api_key=gemini_key
                    )

                    score = analysis.get("overall_risk_score", "UNKNOWN")
                    badge_colors = {
                        "CRITICAL": "red",
                        "HIGH": "orange",
                        "MEDIUM": "blue",
                        "LOW": "green"
                    }
                    badge_color = badge_colors.get(score.upper(), "grey")

                    st.markdown(f"### Contextual Posture: :{badge_color}[{score.upper()}]")
                    st.write(f"**Executive Summary:** {analysis.get('executive_summary', '')}")

                    with st.expander("🔍 Attack Path & Vector Synthesis", expanded=True):
                        st.write(analysis.get("attack_path_analysis", "No path identified."))

                    st.markdown("#### 🛠️ Prioritized Remediation Roadmap")
                    actions = analysis.get("prioritized_actions", [])
                    if actions:
                        st.dataframe(pd.DataFrame(actions), use_container_width=True)
                    else:
                        st.info("No specific actions generated.")

                    add_audit_entry("AI Correlation & Risk Scoring", "SUCCESS")
                except Exception as err:
                    st.error(f"Correlation failed: {err}")
                    add_audit_entry("AI Correlation", f"FAILED: {err}")

# Sidebar: Live Audit Log
st.sidebar.markdown("---")
st.sidebar.title("📋 Activity Audit Log")
if st.session_state.audit_log:
    for entry in reversed(st.session_state.audit_log):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n{'-'*25}")
else:
    st.sidebar.caption("No activities recorded yet.")