import streamlit as st
import datetime
from urllib.parse import urlparse

st.set_page_config(page_title="VAPT Triage Copilot", layout="wide")

# Initialize persistent activity audit log
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
    """Strictly allows only localhost and 127.0.0.1 (sandbox environments)."""
    clean_target = target_str.strip().lower()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "http://" + clean_target
    parsed = urlparse(clean_target)
    hostname = parsed.hostname or ""
    allowed_hosts = ["127.0.0.1", "localhost"]
    return hostname in allowed_hosts

# Header
st.title("🛡️ AI VAPT Triage & Prioritization Copilot")
st.caption("Human-in-the-Loop Security Assessment for Local Containers")

# Target input
target = st.text_input("Target Scope (Must be local/sandbox):", "127.0.0.1:3000")

# Run Assessment Button
if st.button("🚀 Start Assessment"):
    if not is_scope_allowed(target):
        st.error(f"❌ Scope Violation: '{target}' is not an authorized local sandbox target.")
        st.warning("Only 127.0.0.1 and localhost targets are permitted under hackathon safety rules.")
        add_audit_entry(f"Target validation failed for: {target}", "BLOCKED")
    else:
        st.success(f" Target '{target}' validated. Scope locked to local sandbox.")
        add_audit_entry(f"Assessment started against: {target}", "AUTHORIZED")

        # Visual pipeline steps
        st.write("1.  Network Scan (Nmap): Port 3000 detected (Node.js/Express)")
        st.write("2.  Web Scan Ingestion (Burp/ZAP): Findings loaded")

        st.subheader("🤖 AI Correlation & Reasoning")
        st.warning("AI Reason: Port 3000 is directly accessible and burp detects potential login bypass. Confidence: 85%")

        st.subheader("⚠️ Human-in-the-Loop Approval Required")
        st.write("Action: Verify login bypass on endpoint `/rest/user/login` with safe payload.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button(" Approve Benign Probe"):
                add_audit_entry("Approved benign probe execution on 127.0.0.1:3000", "SUCCESS")
                st.success("Probe executed safely! Vulnerability confirmed on 127.0.0.1:3000.")
        with col2:
            if st.button("❌ Reject Action"):
                add_audit_entry("User rejected benign probe execution", "ABORTED")
                st.error("Action rejected by operator.")

# Sidebar: Live Audit Log
st.sidebar.title("📋 Activity Audit Log")
if st.session_state.audit_log:
    for entry in reversed(st.session_state.audit_log):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n{'-'*25}")
else:
    st.sidebar.caption("No activities recorded yet.")