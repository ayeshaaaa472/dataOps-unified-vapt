import streamlit as st
import datetime
import os
from urllib.parse import urlparse
from parser import parse_nmap_xml, parse_zap_json
from scanner import run_nmap_scan

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
    """Verifies target is within authorized local lab boundaries."""
    clean_target = target_str.strip().lower()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    hostname = parsed.hostname or ""
    # Permitted local lab addresses
    allowed_hosts = ["127.0.0.1", "localhost"]
    return hostname in allowed_hosts

st.title("🛡️ AI VAPT Triage & Prioritization Copilot")
st.caption("Human-in-the-Loop Security Assessment for Local Containers")

target_input = st.text_input("Target Scope (Local sandbox):", "127.0.0.1:3000")

if st.button("🚀 Start Assessment"):
    # Extract host and port dynamically
    clean_target = target_input.strip()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    target_ip = parsed.hostname or "127.0.0.1"
    target_port = str(parsed.port or "3000")

    if not is_scope_allowed(target_input):
        st.error(f"❌ Scope Violation: '{target_input}' is outside permitted local scope.")
        add_audit_entry(f"Scope violation for {target_input}", "BLOCKED")
    else:
        add_audit_entry(f"Assessment started against {target_ip}:{target_port}", "AUTHORIZED")
        st.success(f"Target '{target_ip}:{target_port}' locked and authorized.")

        # 1. Run Live Scanner
        with st.spinner("Running network reconnaissance..."):
            scan_res = run_nmap_scan(target_ip=target_ip, port=target_port)
            network_findings = scan_res.get("findings", [])

        # 2. Ingest Application Scans (ZAP/Burp imports)
        zap_file = os.path.join("imports", "sample_zap_report.json")
        web_findings = parse_zap_json(zap_file)

        # Merge findings
        all_findings = network_findings + web_findings

        st.subheader("📊 Ingested Tool Findings")
        if all_findings:
            for item in all_findings:
                with st.expander(f"[{item['severity'].upper()}] {item['title']} ({item['tool']})"):
                    st.write(f"**Target:** `{item['target']}:{item['port']}`")
                    st.write(f"**Evidence:** `{item['evidence']}`")
                    st.write(f"**Description:** {item['description']}")
        else:
            st.info("No open ports or findings detected for this target.")

# Sidebar: Live Audit Log
st.sidebar.title("📋 Activity Audit Log")
if st.session_state.audit_log:
    for entry in reversed(st.session_state.audit_log):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n{'-'*25}")
else:
    st.sidebar.caption("No activities recorded yet.")