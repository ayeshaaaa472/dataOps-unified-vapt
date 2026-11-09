import os
import json
import datetime
from urllib.parse import urlparse
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from nmap_scanner import execute_and_export, validate_target
from parser import parse_zap_json, parse_nikto_json
from ai_correlator import correlate_and_deduplicate, run_ai_correlation
from prober import execute_benign_probe
from report_generator import generate_pdf_report

load_dotenv()

# 1. Page title and icon
st.set_page_config(
    page_title="VAPT Copilot",
    page_icon="🛡️",
    layout="wide"
)

AUDIT_LOG_FILE = "audit_log.jsonl"

def add_audit_entry(action: str, status: str):
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "status": status
    }
    if "audit_log" not in st.session_state:
        st.session_state["audit_log"] = []
    st.session_state["audit_log"].append(entry)
    
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

if "audit_log" not in st.session_state:
    st.session_state["audit_log"] = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        st.session_state["audit_log"].append(json.loads(line.strip()))
        except Exception:
            pass

# Sidebar: Tool Status and Audit Log
st.sidebar.title("🛠️ Integration Status")
integration_data = {
    "Tool": ["Nmap", "OWASP ZAP", "Nikto"],
    "Type": ["Network", "Web App", "Web Server"],
    "Status": ["Live Subprocess", "Import (JSON)", "Import (JSON)"],
}
st.sidebar.table(pd.DataFrame(integration_data))

st.sidebar.markdown("---")
st.sidebar.title("Activity Audit Log")
if st.session_state["audit_log"]:
    for entry in reversed(st.session_state["audit_log"][-8:]):
        st.sidebar.text(f"[{entry['timestamp']}]\n{entry['action']}\nStatus: {entry['status']}\n-------------------------")
else:
    st.sidebar.caption("No activities recorded yet.")

# Main Interface
st.title("🛡️ VAPT Copilot")
st.caption("Human-in-the-Loop Security Assessment, Verification & Contextual Risk Prioritization")

target_input = st.text_input("Target Scope (Lab IP):", "127.0.0.1:3000")

col_upload1, col_upload2 = st.columns(2)
with col_upload1:
    uploaded_zap = st.file_uploader("Upload OWASP ZAP Report (JSON)", type=["json"])
with col_upload2:
    uploaded_nikto = st.file_uploader("Upload Nikto Report (Optional JSON)", type=["json"])

clean_target = target_input.strip()
if not clean_target.startswith(("http://", "https://")):
    clean_target = "http://" + clean_target
parsed = urlparse(clean_target)
target_host = parsed.hostname or "127.0.0.1"
target_port = str(parsed.port or "3000")

if "request_intent" not in st.session_state:
    st.session_state["request_intent"] = ""

chat_text = st.chat_input("Tell the assistant what to assess (for example: Check the web app on port 3000 for exposure)")
if chat_text:
    st.session_state["request_intent"] = chat_text.strip()

request_intent = st.session_state["request_intent"]
if not request_intent:
    with st.chat_message("assistant"):
        st.markdown("Hi! I am your security assessment assistant. Enter your lab target above, then tell me in the chat box what you'd like me to look into. I will prepare an approval plan before touching anything.")
    st.stop()

# Conversational Execution Plan Card
st.subheader("Assessment Plan")
with st.chat_message("user"):
    st.markdown(f"**Assessment request:** {request_intent}")
    st.caption(f"Target: `{target_host}:{target_port}`")

with st.chat_message("assistant"):
    st.markdown(f"""Understood. Before I run anything, here is my plan for `{target_host}:{target_port}`:

1. `[Network]` **Nmap Service Discovery** (Timeout: 30s) — *Reason: Identify active listening ports to validate web vulnerability exposure.*
2. `[Web]` **OWASP ZAP Ingestion** ({'Custom Upload' if uploaded_zap else 'Sample Dataset'}) — *Reason: Ingest application-layer findings (SQLi, missing security headers).*
3. `[Server]` **Nikto Ingestion** ({'Custom Upload' if uploaded_nikto else 'Sample Dataset'}) — *Reason: Discover web server configuration flaws and information disclosures.*
4. `[Correlation]` **Deterministic Python Cross-Referencing & Multi-Tier AI Synthesis** — *Reason: Deduplicate findings and elevate confidence on open network ports.*

**[Requires Approval]** Nothing runs until you approve this plan with the button below.""")

if st.button("✅ Approve Plan & Execute Assessment", type="primary"):
    # 3. Friendlier wording on scope failure
    if not validate_target(target_host):
        st.error(f"🚫 I can't scan `{target_host}`. It is outside the authorized lab boundary, and I only test local safe targets on your own machine.")
        add_audit_entry(f"Scope violation blocked for target: {target_host}", "BLOCKED")
    else:
        add_audit_entry(f"Plan approved by analyst for {target_host}:{target_port}", "AUTHORIZED")

        # Live progress tracker
        with st.status("Executing assessment according to approved plan...", expanded=True) as status:
            st.write("Validating target boundary and RFC 1918 scope...")
            
            # 1. Live Nmap
            st.write("Running Nmap active service discovery on port " + target_port + "...")
            try:
                network_findings = execute_and_export(target=target_host, ports=target_port)
                add_audit_entry(f"Nmap scan completed: {len(network_findings)} port(s) detected", "OK")
            except Exception as err:
                network_findings = []
                add_audit_entry(f"Nmap execution failed/empty: {err}", "FAILED")

            # 2. ZAP Ingestion
            st.write("⚡ Ingesting OWASP ZAP application vulnerability records...")
            zap_is_sample = uploaded_zap is None
            zap_path = os.path.join("imports", "sample_zap_report.json")
            if uploaded_zap is not None:
                zap_path = os.path.join("imports", "uploaded_temp_zap.json")
                os.makedirs("imports", exist_ok=True)
                with open(zap_path, "wb") as f:
                    f.write(uploaded_zap.getbuffer())
                add_audit_entry("Loaded custom OWASP ZAP JSON export", "OK")
            web_findings = parse_zap_json(zap_path)

            # 3. Nikto Ingestion
            st.write("Ingesting Nikto web server configuration findings...")
            nikto_is_sample = uploaded_nikto is None
            nikto_path = os.path.join("imports", "sample_nikto_report.json")
            if uploaded_nikto is not None:
                nikto_path = os.path.join("imports", "uploaded_temp_nikto.json")
                os.makedirs("imports", exist_ok=True)
                with open(nikto_path, "wb") as f:
                    f.write(uploaded_nikto.getbuffer())
                add_audit_entry("Loaded custom Nikto JSON export", "OK")
            nikto_findings = parse_nikto_json(nikto_path)

            # Correlation
            st.write("Correlating network service reachability with application findings...")
            raw_findings = network_findings + web_findings + nikto_findings
            st.session_state["current_findings"] = correlate_and_deduplicate(raw_findings)
            st.session_state["zap_is_sample"] = zap_is_sample
            st.session_state["nikto_is_sample"] = nikto_is_sample

            # 4. Multi-tier AI
            st.write("Synthesizing contextual risk analysis with AI engine...")
            triage_analysis = run_ai_correlation(st.session_state["current_findings"])
            st.session_state["triage_report"] = triage_analysis
            add_audit_entry(f"Correlation completed via {triage_analysis.get('provider_used')}", "OK")

            status.update(label="✅ Assessment complete!", state="complete", expanded=False)
            st.rerun()

# Results Section
if st.session_state.get("current_findings"):
    st.markdown("---")
    
    # Top Summary Metric Cards
    report = st.session_state.get("triage_report", {})
    findings = st.session_state.get("current_findings", [])
    
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.metric("Total Findings", len(findings))
    with col_m2:
        st.metric("Risk Posture", report.get("overall_risk_score", "MEDIUM"))
    with col_m3:
        st.metric("Triage Engine", report.get("provider_used", "Fallback"))
    with col_m4:
        st.metric("Data Sources", "Nmap (Live) + ZAP + Nikto")

    # Tabs Layout
    tab_findings, tab_report, tab_plan, tab_audit = st.tabs([
        "Correlated Findings",
        "AI Synthesis & PDF Export",
        "Original Plan",
        "Full Audit Trail"
    ])

    with tab_findings:
        st.subheader(f"Ingested & Correlated Findings ({len(findings)})")
        
        # 1. Colored severity markers
        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🔴",
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "INFO": "🔵"
        }

        for idx, finding in enumerate(findings):
            sev = str(finding.get("severity", "INFO")).upper()
            icon = severity_icons.get(sev, "⚪")
            header_label = f"{icon} [{sev}] {finding.get('title')} ({finding.get('tool')})"
            
            with st.expander(header_label):
                col_f1, col_f2 = st.columns(2)
                with col_f1:
                    st.write(f"**Asset:** `{finding.get('target')}:{finding.get('port')}` | **Status:** `{finding.get('status')}`")
                    st.write(f"**Confidence:** `{int(float(finding.get('confidence', 0.8))*100)}%`")
                    st.info(f"**Trust Justification:** {finding.get('trust_reason', 'Single tool report.')}")
                    if finding.get("cwe") and finding.get("cwe") != "N/A":
                        st.caption(f"Classification: {finding.get('cwe')}")
                with col_f2:
                    st.write("**Raw Tool Snippet:**")
                    st.code(finding.get("evidence", "No raw snippet available"))
                    st.caption(f"Raw source: {finding.get('raw_ref', 'N/A')}")

                col_btn1, col_btn2 = st.columns([1, 4])
                with col_btn1:
                    # 2. Highlighted approval button (primary=orange)
                    if st.button("Approve Safe Probe", key=f"probe_{idx}", type="primary"):
                        if not validate_target(str(finding.get("target"))):
                            finding["status"] = "Probe blocked: target outside authorized lab scope"
                            add_audit_entry(f"Probe blocked on {finding.get('id')}: {finding.get('target')}", "BLOCKED")
                            st.rerun()
                        try:
                            probe_result = execute_benign_probe(finding.get("target"), finding.get("port"))
                            raw_code = probe_result.get("status_code", 0)
                            try:
                                sc = int(raw_code)
                            except (ValueError, TypeError):
                                sc = 0
                                
                            if sc > 0:
                                finding["status"] = f"Reachable (HTTP {sc}); vulnerability not confirmed"
                            else:
                                finding["status"] = "Probe Unreachable (Connection Refused)"
                            add_audit_entry(f"Benign probe on {finding.get('id')} -> {finding['status']}", "VERIFIED")
                        except Exception as probe_err:
                            finding["status"] = "Probe Failed"
                            add_audit_entry(f"Probe failed on {finding.get('id')}: {probe_err}", "ERROR")
                        st.rerun()
                        
                with col_btn2:
                    # Plain Reject button
                    if st.button("Reject Finding", key=f"rej_{idx}"):
                        finding["status"] = "Rejected by Analyst"
                        add_audit_entry(f"Finding {finding.get('id')} rejected by analyst", "REJECTED")
                        st.rerun()

    with tab_report:
        if report:
            with st.chat_message("assistant"):
                st.markdown(f"### Executive Triage Summary\n{report.get('executive_summary')}")
                st.markdown(f"**Attack Path Synthesis:**\n{report.get('attack_path_analysis')}")

            if report.get("fallback_reason"):
                st.info(f"ℹEngine Note: Deterministic local rules engaged ({report.get('fallback_reason')})")

            rejected_ids = {str(f.get("id")) for f in findings if f.get("status") == "Rejected by Analyst"}
            active_actions = [a for a in report.get("prioritized_actions", []) if str(a.get("finding_id")) not in rejected_ids]
            if active_actions:
                st.write("### Prioritized Remediation Roadmap")
                st.table(pd.DataFrame(active_actions))

            st.markdown("---")
            st.subheader("Export Assessment Report")
            try:
                pdf_bytes = generate_pdf_report(
                    target=target_input,
                    analysis_data=report,
                    findings=findings,
                    audit_log=st.session_state.get("audit_log", []),
                    zap_is_sample=st.session_state.get("zap_is_sample", True),
                    nikto_is_sample=st.session_state.get("nikto_is_sample", True)
                )
                st.download_button(
                    label="📥 Download Full VAPT Audit Report (PDF)",
                    data=pdf_bytes,
                    file_name=f"VAPT_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"Error generating PDF report: {e}")

    with tab_plan:
        st.info(f"**Target:** `{target_host}:{target_port}`")
        st.write(f"**Intent:** {request_intent}")
        st.markdown("""
        * Scope verified against RFC 1918 loopback boundaries.
        * Live Nmap service identification executed on target port.
        * Web and server vulnerability imports correlated against open network services.
        * Human oversight required before any probe execution.
        """)

    with tab_audit:
        st.subheader("Immutable Audit Trail")
        if st.session_state.get("audit_log"):
            st.dataframe(pd.DataFrame(st.session_state["audit_log"]), use_container_width=True)
        else:
            st.caption("No audit entries recorded.")