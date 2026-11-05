import streamlit as st
import datetime
import os
from urllib.parse import urlparse
from parser import parse_nmap_xml, parse_zap_json
from scanner import run_nmap_scan

st.set_page_config(page_title="VAPT Triage Copilot", layout="wide")

# ---------------------------------------------------------
# State Initialization (Persistent across UI re-renders)
# ---------------------------------------------------------
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "scan_findings" not in st.session_state:
    st.session_state.scan_findings = []

if "last_target" not in st.session_state:
    st.session_state.last_target = ""


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------
def add_audit_entry(action: str, status: str):
    """Appends an event to the persistent session audit trail."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.audit_log.append({
        "timestamp": timestamp,
        "action": action,
        "status": status
    })


def is_scope_allowed(target_str: str) -> bool:
    """Verifies target is within authorized local lab boundaries."""
    clean_target = target_str.strip().lower()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    hostname = parsed.hostname or ""
    allowed_hosts = ["127.0.0.1", "localhost"]
    return hostname in allowed_hosts


# ---------------------------------------------------------
# UI Layout & Input Controls
# ---------------------------------------------------------
st.title("🛡️ AI VAPT Triage & Prioritization Copilot")
st.caption("Standardized Multi-Tool Ingestion & Assessment Pipeline")

col1, col2 = st.columns([3, 1])
with col1:
    target_input = st.text_input("Target Address (Host:Port):", value="127.0.0.1:3000")
with col2:
    st.write("")
    st.write("")
    scan_button = st.button("🚀 Run Assessment", use_container_width=True)

# ---------------------------------------------------------
# Execution Pipeline Trigger
# ---------------------------------------------------------
if scan_button:
    # 1. Reset current findings to prevent stale or duplicated data
    st.session_state.scan_findings = []
    
    clean_target = target_input.strip()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    target_ip = parsed.hostname or "127.0.0.1"
    target_port = str(parsed.port or "3000")
    st.session_state.last_target = f"{target_ip}:{target_port}"

    # 2. Scope Validation
    if not is_scope_allowed(target_input):
        add_audit_entry(f"Scope violation attempt: {target_input}", "BLOCKED")
        st.error(f"❌ Scope Violation: Target '{target_input}' is outside authorized local boundaries.")
    else:
        add_audit_entry(f"Assessment triggered on {target_ip}:{target_port}", "AUTHORIZED")
        
        # 3. Network Discovery via scanner wrapper
        with st.spinner(f"Scanning target {target_ip}:{target_port}..."):
            scan_res = run_nmap_scan(target_ip=target_ip, port=target_port)
            network_findings = scan_res.get("findings", [])

        # 4. Ingest Application Scanner Data via parser
        zap_file = os.path.join("imports", "sample_zap_report.json")
        web_findings = parse_zap_json(zap_file)

        # 5. Commit merged findings to session state
        st.session_state.scan_findings = network_findings + web_findings
        add_audit_entry(f"Loaded {len(st.session_state.scan_findings)} normalized findings", "SUCCESS")

# ---------------------------------------------------------
# Render Results (Preserved across minor re-renders)
# ---------------------------------------------------------
if st.session_state.scan_findings:
    st.markdown(f"### Assessment Results: `{st.session_state.last_target}`")
    st.info(f"Total Unified Findings: **{len(st.session_state.scan_findings)}**")
    
    for item in st.session_state.scan_findings:
        badge_color = {
            "High": "🔴",
            "Medium": "🟠",
            "Low": "🟡",
            "Info": "🔵"
        }.get(item.get("severity", "Info"), "⚪")

        header = f"{badge_color} [{item['severity'].upper()}] {item['title']} ({item['tool']})"
        with st.expander(header, expanded=(item["severity"] == "High")):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(f"**ID:** `{item['id']}`")
                st.markdown(f"**Target:** `{item['target']}:{item['port']}`")
            with col_b:
                st.markdown(f"**Confidence:** `{item['confidence']}`")
                st.markdown(f"**CVE Reference:** `{item['cve']}`")
            
            st.markdown(f"**Evidence:** `{item['evidence']}`")
            if item.get("description"):
                st.markdown(f"**Description:** {item['description']}")

elif scan_button and is_scope_allowed(target_input):
    st.warning("No open services or vulnerability findings were returned for this scan.")

# ---------------------------------------------------------
# Sidebar: Audit Log
# ---------------------------------------------------------
st.sidebar.title("📋 Activity Audit Log")
if st.sidebar.button("Clear Log", use_container_width=True):
    st.session_state.audit_log = []
    st.rerun()

if st.session_state.audit_log:
    for entry in reversed(st.session_state.audit_log):
        st.sidebar.text(
            f"[{entry['timestamp']}]\n"
            f"Action: {entry['action']}\n"
            f"Status: {entry['status']}\n"
            f"{'-'*28}"
        )
else:
    st.sidebar.caption("No audit entries recorded.")